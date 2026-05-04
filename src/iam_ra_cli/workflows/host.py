"""Host workflows - onboard, offboard, list hosts."""

from dataclasses import dataclass
from pathlib import Path

from iam_ra_cli.lib import state as state_module
from iam_ra_cli.lib.aws import AwsContext
from iam_ra_cli.lib.errors import (
    CAScopeNotFoundError,
    HostAlreadyExistsError,
    HostNotFoundError,
    NotInitializedError,
    RoleNotFoundError,
    SecretsError,
    StackDeleteError,
    StateLoadError,
    StateSaveError,
)
from iam_ra_cli.lib.result import Err, Ok, Result
from iam_ra_cli.lib.sops import SopsProfile
from iam_ra_cli.models import Arn, CAMode, Host
from iam_ra_cli.operations.host import (
    HostError,
    onboard_host_pca,
    onboard_host_self_signed,
)
from iam_ra_cli.operations.host import (
    offboard_host as offboard_host_op,
)
from iam_ra_cli.operations.secrets import SecretsFileResult, create_secrets_file

type OnboardError = (
    NotInitializedError
    | RoleNotFoundError
    | CAScopeNotFoundError
    | HostAlreadyExistsError
    | HostError
    | SecretsError
    | StateSaveError
    | StateLoadError
)
type OffboardError = (
    NotInitializedError | HostNotFoundError | StackDeleteError | StateSaveError | StateLoadError
)
type ListHostsError = NotInitializedError | StateLoadError


@dataclass(frozen=True)
class OnboardConfig:
    """Configuration for onboard workflow.

    v3: role_names is a tuple - one cert can authenticate against multiple
    AWS roles, as long as they all share the same scope (same trust anchor).
    The CLI accepts --role X,Y,Z or repeated --role flags; both produce a
    tuple here.
    """

    namespace: str
    hostname: str
    role_names: tuple[str, ...]
    validity_days: int = 365
    create_sops: bool = True
    sops_output_path: Path | None = None
    overwrite: bool = False


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


@dataclass(frozen=True)
class OnboardResult:
    """Result of onboard workflow.

    Carries everything the CLI needs to guide the user through their
    post-onboard setup (Nix config, AWS CLI verification, etc.), sourced
    from state during the workflow so the CLI layer doesn't need to reach
    back into state itself.

    v3: role_profiles replaces scalar profile_arn/role_arn. A host can be
    onboarded with multiple roles that share a cert; this surfaces all of
    them so the CLI can render multi-profile Nix snippets.
    """

    host: Host
    secrets_file: SecretsFileResult | None
    namespace: str
    region: str
    trust_anchor_arn: Arn
    role_profiles: tuple[RoleProfile, ...]


def onboard(ctx: AwsContext, config: OnboardConfig) -> Result[OnboardResult, OnboardError]:
    """Onboard a host to IAM Roles Anywhere.

    1. Load state, validate initialized
    2. Validate all roles exist and share the same scope
    3. Check host doesn't already exist (unless overwrite)
    4. Generate cert based on CA mode
    5. Deploy host stack
    6. Create SOPS file (if requested)
    7. Update state
    """
    # Load state
    match state_module.load(ctx.ssm, ctx.s3, config.namespace):
        case Err(e):
            return Err(e)
        case Ok(None):
            return Err(NotInitializedError(config.namespace))
        case Ok(state):
            pass

    if not state.is_initialized:
        return Err(NotInitializedError(config.namespace))

    assert state.init is not None

    if not config.role_names:
        # Empty tuple - caller bug. Treat as role-not-found for now with
        # an empty name (CLI validates earlier so this is defensive).
        return Err(RoleNotFoundError(config.namespace, ""))

    # Validate all roles exist
    for role_name in config.role_names:
        if role_name not in state.roles:
            return Err(RoleNotFoundError(config.namespace, role_name))

    roles = tuple(state.roles[name] for name in config.role_names)

    # Validate all roles share the same scope (a single cert only
    # authenticates against one trust anchor; multi-role requires same scope)
    scopes = {r.scope for r in roles}
    if len(scopes) > 1:
        # Different scopes for different roles means different trust anchors
        # means different certs. Reject here; scenario 3 (multi-identity)
        # will address this via multi-namespace onboarding, not via multi-
        # role in one onboard call.
        return Err(
            CAScopeNotFoundError(
                config.namespace,
                f"Roles {list(config.role_names)} span multiple scopes "
                f"{sorted(scopes)}; all roles for one host must share a scope",
            )
        )
    scope = roles[0].scope

    # Validate scope has a CA set up
    if scope not in state.cas:
        return Err(CAScopeNotFoundError(config.namespace, scope))

    scope_ca = state.cas[scope]

    # Check host doesn't already exist
    if config.hostname in state.hosts and not config.overwrite:
        return Err(HostAlreadyExistsError(config.namespace, config.hostname))

    bucket_name = state.init.bucket_arn.resource_id

    # Generate cert and deploy host stack based on CA mode
    match scope_ca.mode:
        case CAMode.SELF_SIGNED:
            match onboard_host_self_signed(
                ctx,
                config.namespace,
                config.hostname,
                bucket_name,
                config.validity_days,
                scope=scope,
            ):
                case Err() as e:
                    return e
                case Ok(host_result):
                    pass

        case CAMode.PCA_NEW | CAMode.PCA_EXISTING:
            assert scope_ca.pca_arn is not None
            match onboard_host_pca(
                ctx,
                config.namespace,
                config.hostname,
                str(scope_ca.pca_arn),
                bucket_name,
                config.validity_days,
                scope=scope,
            ):
                case Err() as e:
                    return e
                case Ok(host_result):
                    pass

    # Create Host model (v3: role_names tuple, explicit scope)
    new_host = Host(
        stack_name=host_result.stack_name,
        hostname=config.hostname,
        role_names=tuple(config.role_names),
        scope=scope,
        certificate_secret_arn=host_result.certificate_secret_arn,
        private_key_secret_arn=host_result.private_key_secret_arn,
    )

    # Build RoleProfile records for the result
    role_profiles = tuple(
        RoleProfile(role_name=r_name, role_arn=r.role_arn, profile_arn=r.profile_arn)
        for r_name, r in zip(config.role_names, roles)
    )

    # Update state
    state.hosts[config.hostname] = new_host
    match state_module.save(ctx.ssm, ctx.s3, state):
        case Err() as e:
            return e
        case Ok(_):
            pass

    # Create SOPS secrets file if requested
    # The v2 SOPS schema stores all role_profiles under a nested 'profiles'
    # map (not just the first role). A host onboarded with N roles writes N
    # profile entries into the SOPS file.
    secrets_result: SecretsFileResult | None = None
    if config.create_sops:
        sops_profiles = tuple(
            SopsProfile(
                role_name=rp.role_name,
                profile_arn=str(rp.profile_arn),
                role_arn=str(rp.role_arn),
            )
            for rp in role_profiles
        )
        # account_id: prefer the one already recorded on the CA; fall back
        # to deriving from the trust anchor ARN if unset (v2 state that
        # hasn't been migrated / resaved yet).
        account_id = scope_ca.account_id or scope_ca.trust_anchor_arn.account
        match create_secrets_file(
            ctx,
            hostname=config.hostname,
            certificate_secret_arn=str(host_result.certificate_secret_arn),
            private_key_secret_arn=str(host_result.private_key_secret_arn),
            trust_anchor_arn=str(scope_ca.trust_anchor_arn),
            account_id=account_id,
            profiles=sops_profiles,
            output_path=config.sops_output_path,
            overwrite=config.overwrite,
        ):
            case Err() as e:
                # Don't fail the whole workflow for secrets file error
                # The host is already onboarded at this point
                return e
            case Ok(result):
                secrets_result = result

    return Ok(
        OnboardResult(
            host=new_host,
            secrets_file=secrets_result,
            namespace=config.namespace,
            region=ctx.region,
            trust_anchor_arn=scope_ca.trust_anchor_arn,
            role_profiles=role_profiles,
        )
    )


def offboard(
    ctx: AwsContext,
    namespace: str,
    hostname: str,
) -> Result[None, OffboardError]:
    """Offboard a host from IAM Roles Anywhere.

    1. Load state
    2. Check host exists
    3. Delete host stack
    4. Cleanup S3
    5. Update state
    """
    # Load state
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

    # Check host exists
    if hostname not in state.hosts:
        return Err(HostNotFoundError(namespace, hostname))

    host = state.hosts[hostname]
    bucket_name = state.init.bucket_arn.resource_id

    # Delete host stack and cleanup S3
    match offboard_host_op(ctx, host.stack_name, bucket_name, namespace, hostname):
        case Err() as e:
            return e
        case Ok(_):
            pass

    # Update state
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
