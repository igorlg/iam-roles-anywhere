"""Host lifecycle workflows - offboard, list, add/remove role.

Enrolment moved to :mod:`iam_ra_cli.workflows.enrol` in v3. What remains here is
the rest of a host's lifecycle after it has a certificate.

Two v2 workflows were removed rather than ported:

``onboard``
    Generated the host's private key on the admin workstation and escrowed it in
    S3 + Secrets Manager. Replaced by ``request``/``approve``/``enrol``.

``rotate_cert``
    Rotated a host's key *from the admin workstation*, which is only possible
    while the admin holds the key. Under v3 the key lives on the host and never
    leaves, so rotation is necessarily a host-side action: re-run
    ``iam-ra host enroll --overwrite`` there, or ``host request --overwrite``
    plus ``host approve --overwrite`` for a split enrolment.

``add_role`` and ``remove_role`` no longer rewrite a SOPS file. Under v3 the
profile list lives in the host's Nix configuration and the certificate carries
no role information, so these only update state - which roles a host is
*recorded* as using. The user still has to add or remove the matching
``profiles.<name>`` entry in Nix.
"""

from dataclasses import dataclass, replace

from iam_ra_cli.lib import state as state_module
from iam_ra_cli.lib.aws import AwsContext
from iam_ra_cli.lib.errors import (
    AccountMismatchError,
    CannotRemoveLastRoleError,
    HostNotFoundError,
    NotInitializedError,
    RoleNotFoundError,
    RoleScopeMismatchError,
    StackDeleteError,
    StateLoadError,
    StateSaveError,
)
from iam_ra_cli.lib.preflight import check_account_matches_namespace
from iam_ra_cli.lib.result import Err, Ok, Result
from iam_ra_cli.models import Arn, Host
from iam_ra_cli.operations.host import (
    offboard_host as offboard_host_op,
)

type OffboardError = (
    NotInitializedError
    | AccountMismatchError
    | HostNotFoundError
    | StackDeleteError
    | StateSaveError
    | StateLoadError
)
type ListHostsError = NotInitializedError | StateLoadError

type AddRoleError = (
    NotInitializedError
    | AccountMismatchError
    | HostNotFoundError
    | RoleNotFoundError
    | RoleScopeMismatchError
    | StateLoadError
    | StateSaveError
)

type RemoveRoleError = (
    NotInitializedError
    | AccountMismatchError
    | HostNotFoundError
    | RoleNotFoundError
    | CannotRemoveLastRoleError
    | StateLoadError
    | StateSaveError
)


@dataclass(frozen=True)
class RoleProfile:
    """A (role_name, role_arn, profile_arn) triple.

    Each represents one assumable identity backed by a single cert. A host
    can have many of these - all sharing a scope and thus a cert - but each
    maps to its own IAM role + Roles Anywhere profile.
    """

    role_name: str
    role_arn: Arn
    profile_arn: Arn


# =============================================================================
# offboard
# =============================================================================


def offboard(
    ctx: AwsContext,
    namespace: str,
    hostname: str,
) -> Result[None, OffboardError]:
    """Remove a host from the namespace.

    For a legacy v2/v3 host this deletes its CloudFormation stack (and with it
    the Secrets Manager secrets) plus its S3 objects. For a v4 host there is
    nothing in AWS to remove, so it is purely a state deletion.

    Note this does **not** revoke the certificate. There is no revocation
    mechanism, so an offboarded host's certificate stays valid against the trust
    anchor until it expires. Short certificate lifetimes are the mitigation.
    """
    match state_module.load(ctx.ssm, ctx.s3, namespace):
        case Err(e):
            return Err(e)
        case Ok(None):
            return Err(NotInitializedError(namespace))
        case Ok(state):
            pass

    if not state.is_initialized:
        return Err(NotInitializedError(namespace))

    assert state.init is not None

    # Fail fast if current credentials are for the wrong AWS account.
    match check_account_matches_namespace(ctx, state):
        case Err() as e:
            return e
        case Ok(_):
            pass

    if hostname not in state.hosts:
        return Err(HostNotFoundError(namespace, hostname))

    host = state.hosts[hostname]
    bucket_name = state.init.bucket_arn.resource_id

    # v4 hosts have no CloudFormation stack and no S3 objects: the key was
    # generated on the host and the certificate was never uploaded. Skipping is
    # not just an optimisation - passing a None stack name to CloudFormation
    # would fail.
    if host.stack_name is not None:
        match offboard_host_op(ctx, host.stack_name, bucket_name, namespace, hostname):
            case Err() as e:
                return e
            case Ok(_):
                pass

    del state.hosts[hostname]
    match state_module.save(ctx.ssm, ctx.s3, state):
        case Err() as e:
            return e
        case Ok(_):
            pass

    return Ok(None)


def list_hosts(ctx: AwsContext, namespace: str) -> Result[dict[str, Host], ListHostsError]:
    """List all hosts in a namespace."""
    match state_module.load(ctx.ssm, ctx.s3, namespace):
        case Err(e):
            return Err(e)
        case Ok(None):
            return Err(NotInitializedError(namespace))
        case Ok(state):
            return Ok(state.hosts)


# =============================================================================
# add_role / remove_role (scenario 2: multi-role, same cert)
# =============================================================================


@dataclass(frozen=True)
class AddRoleConfig:
    """Configuration for add_role workflow."""

    namespace: str
    hostname: str
    role_name: str


@dataclass(frozen=True)
class AddRoleResult:
    """Result of add_role workflow.

    `already_present` is True when the role was already attached (no-op);
    callers can surface this to distinguish "I did work" from "nothing to do".

    `role_profile` carries the ARNs the user needs to add to their Nix
    configuration, since nothing writes them out on their behalf any more.
    """

    hostname: str
    role_name: str
    already_present: bool
    updated_role_names: tuple[str, ...]
    role_profile: RoleProfile


@dataclass(frozen=True)
class RemoveRoleConfig:
    """Configuration for remove_role workflow."""

    namespace: str
    hostname: str
    role_name: str


@dataclass(frozen=True)
class RemoveRoleResult:
    """Result of remove_role workflow.

    `already_absent` is True when the role wasn't attached to begin with
    (no-op); callers can surface this.
    """

    hostname: str
    role_name: str
    already_absent: bool
    updated_role_names: tuple[str, ...]


def add_role(ctx: AwsContext, config: AddRoleConfig) -> Result[AddRoleResult, AddRoleError]:
    """Record that a host may assume an additional role.

    Updates state only. No new certificate is issued, because a certificate
    carries no role information - the binding is cert -> CA -> trust anchor,
    and separately role/profile ARNs in the host's Nix configuration. The caller
    still has to add the matching ``profiles.<name>`` entry there.

    Preconditions:
        - Namespace initialised.
        - Host exists.
        - Role exists.
        - Role's scope matches the host's scope (same trust anchor).

    Idempotent: if the role is already attached, returns Ok with
    already_present=True and writes nothing.
    """
    match state_module.load(ctx.ssm, ctx.s3, config.namespace):
        case Err(e):
            return Err(e)
        case Ok(None):
            return Err(NotInitializedError(config.namespace))
        case Ok(state):
            pass

    if not state.is_initialized:
        return Err(NotInitializedError(config.namespace))

    match check_account_matches_namespace(ctx, state):
        case Err() as e:
            return e
        case Ok(_):
            pass

    if config.hostname not in state.hosts:
        return Err(HostNotFoundError(config.namespace, config.hostname))
    host = state.hosts[config.hostname]

    if config.role_name not in state.roles:
        return Err(RoleNotFoundError(config.namespace, config.role_name))
    role = state.roles[config.role_name]

    # A host's cert authenticates against exactly one trust anchor, so a role
    # from another scope is unusable with it. Crossing scopes needs a second
    # identity (and therefore a second cert).
    if role.scope != host.scope:
        return Err(
            RoleScopeMismatchError(
                namespace=config.namespace,
                hostname=config.hostname,
                host_scope=host.scope,
                role_name=config.role_name,
                role_scope=role.scope,
            )
        )

    role_profile = RoleProfile(
        role_name=config.role_name,
        role_arn=role.role_arn,
        profile_arn=role.profile_arn,
    )

    if config.role_name in host.role_names:
        return Ok(
            AddRoleResult(
                hostname=config.hostname,
                role_name=config.role_name,
                already_present=True,
                updated_role_names=host.role_names,
                role_profile=role_profile,
            )
        )

    new_role_names = (*host.role_names, config.role_name)
    state.hosts[config.hostname] = replace(host, role_names=new_role_names)

    match state_module.save(ctx.ssm, ctx.s3, state):
        case Err() as e:
            return e
        case Ok(_):
            pass

    return Ok(
        AddRoleResult(
            hostname=config.hostname,
            role_name=config.role_name,
            already_present=False,
            updated_role_names=new_role_names,
            role_profile=role_profile,
        )
    )


def remove_role(
    ctx: AwsContext, config: RemoveRoleConfig
) -> Result[RemoveRoleResult, RemoveRoleError]:
    """Record that a host may no longer assume a role.

    Updates state only. The caller must also remove the matching
    ``profiles.<name>`` entry from the host's Nix configuration - until they do,
    the host can still assume the role, because authorisation comes from the IAM
    role's trust policy and the profile ARN, not from this record.

    Refuses to remove the last role: a host with none has a certificate but
    nothing to assume. Use ``iam-ra host offboard`` for that.

    Idempotent: if the role isn't attached, returns Ok with
    already_absent=True and writes nothing.
    """
    match state_module.load(ctx.ssm, ctx.s3, config.namespace):
        case Err(e):
            return Err(e)
        case Ok(None):
            return Err(NotInitializedError(config.namespace))
        case Ok(state):
            pass

    if not state.is_initialized:
        return Err(NotInitializedError(config.namespace))

    match check_account_matches_namespace(ctx, state):
        case Err() as e:
            return e
        case Ok(_):
            pass

    if config.hostname not in state.hosts:
        return Err(HostNotFoundError(config.namespace, config.hostname))
    host = state.hosts[config.hostname]

    if config.role_name not in host.role_names:
        return Ok(
            RemoveRoleResult(
                hostname=config.hostname,
                role_name=config.role_name,
                already_absent=True,
                updated_role_names=host.role_names,
            )
        )

    if len(host.role_names) == 1:
        return Err(
            CannotRemoveLastRoleError(
                namespace=config.namespace,
                hostname=config.hostname,
                role_name=config.role_name,
            )
        )

    new_role_names = tuple(r for r in host.role_names if r != config.role_name)
    state.hosts[config.hostname] = replace(host, role_names=new_role_names)

    match state_module.save(ctx.ssm, ctx.s3, state):
        case Err() as e:
            return e
        case Ok(_):
            pass

    return Ok(
        RemoveRoleResult(
            hostname=config.hostname,
            role_name=config.role_name,
            already_absent=False,
            updated_role_names=new_role_names,
        )
    )
