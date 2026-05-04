"""Host workflows - onboard, offboard, list, add/remove role."""

from dataclasses import dataclass, replace
from pathlib import Path

from iam_ra_cli.lib import state as state_module
from iam_ra_cli.lib.aws import AwsContext
from iam_ra_cli.lib.errors import (
    CACertNotFoundError,
    CAKeyNotFoundError,
    CannotRemoveLastRoleError,
    CAScopeNotFoundError,
    HostAlreadyExistsError,
    HostNotFoundError,
    NotInitializedError,
    PCADescribeError,
    PCAGetCertError,
    PCAIssueCertError,
    PCANotActiveError,
    PCATimeoutError,
    RoleNotFoundError,
    RoleScopeMismatchError,
    S3ReadError,
    SecretsError,
    SecretsManagerReadError,
    SOPSEncryptError,
    StackDeleteError,
    StateLoadError,
    StateSaveError,
)
from iam_ra_cli.lib.result import Err, Ok, Result
from iam_ra_cli.lib.sops import (
    SopsProfile,
    create_secrets_yaml,
    decrypt_file,
    get_secrets_path,
    parse_secrets_yaml,
    write_and_encrypt,
)
from iam_ra_cli.models import CA, Arn, CAMode, Host
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

type AddRoleError = (
    NotInitializedError
    | HostNotFoundError
    | RoleNotFoundError
    | RoleScopeMismatchError
    | SOPSEncryptError
    | StateLoadError
    | StateSaveError
)

type RemoveRoleError = (
    NotInitializedError
    | HostNotFoundError
    | RoleNotFoundError
    | CannotRemoveLastRoleError
    | SOPSEncryptError
    | StateLoadError
    | StateSaveError
)

type RotateCertError = (
    NotInitializedError
    | HostNotFoundError
    | CAScopeNotFoundError
    | CAKeyNotFoundError
    | CACertNotFoundError
    | S3ReadError
    | SecretsManagerReadError
    | PCADescribeError
    | PCANotActiveError
    | PCAIssueCertError
    | PCATimeoutError
    | PCAGetCertError
    | SOPSEncryptError
    | StateLoadError
    | StateSaveError
)


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


# =============================================================================
# add_role / remove_role (scenario 2: multi-role, same cert)
# =============================================================================


@dataclass(frozen=True)
class AddRoleConfig:
    """Configuration for add_role workflow."""

    namespace: str
    hostname: str
    role_name: str
    sops_path: Path | None = None  # Override; defaults to get_secrets_path(hostname)


@dataclass(frozen=True)
class AddRoleResult:
    """Result of add_role workflow.

    `already_present` is True when the role was already attached (no-op);
    callers can surface this to distinguish "I did work" from "nothing to do".
    """

    hostname: str
    role_name: str
    already_present: bool
    sops_file_path: Path
    updated_role_names: tuple[str, ...]


@dataclass(frozen=True)
class RemoveRoleConfig:
    """Configuration for remove_role workflow."""

    namespace: str
    hostname: str
    role_name: str
    sops_path: Path | None = None


@dataclass(frozen=True)
class RemoveRoleResult:
    """Result of remove_role workflow.

    `already_absent` is True when the role wasn't attached to begin with
    (no-op); callers can surface this.
    """

    hostname: str
    role_name: str
    already_absent: bool
    sops_file_path: Path
    updated_role_names: tuple[str, ...]


def _resolve_sops_path(hostname: str, override: Path | None) -> Result[Path, SOPSEncryptError]:
    """Resolve the SOPS file path, or return an error if we can't find
    a Nix flake root and the caller didn't override.
    """
    if override is not None:
        return Ok(override)
    try:
        return Ok(get_secrets_path(hostname))
    except RuntimeError as e:
        return Err(SOPSEncryptError(Path("."), str(e)))


def add_role(ctx: AwsContext, config: AddRoleConfig) -> Result[AddRoleResult, AddRoleError]:
    """Attach an additional role to an existing host.

    Does NOT issue a new cert or redeploy the host stack. Updates the
    host's role_names in state and appends a new SopsProfile to the
    SOPS secrets file.

    Preconditions:
        - Namespace initialised.
        - Host exists.
        - Role exists.
        - Role's scope matches the host's scope (same trust anchor).

    Idempotent: if the role is already attached, returns Ok with
    already_present=True and does not rewrite the SOPS file.
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

    # Host must exist
    if config.hostname not in state.hosts:
        return Err(HostNotFoundError(config.namespace, config.hostname))
    host = state.hosts[config.hostname]

    # Role must exist
    if config.role_name not in state.roles:
        return Err(RoleNotFoundError(config.namespace, config.role_name))
    role = state.roles[config.role_name]

    # Scope check: role must live in the same scope as the host's cert
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

    # Resolve SOPS path up-front so errors surface before we do work
    match _resolve_sops_path(config.hostname, config.sops_path):
        case Err(e):
            return Err(e)
        case Ok(sops_path):
            pass

    # Idempotency: role already attached -> no-op success
    if config.role_name in host.role_names:
        return Ok(
            AddRoleResult(
                hostname=config.hostname,
                role_name=config.role_name,
                already_present=True,
                sops_file_path=sops_path,
                updated_role_names=host.role_names,
            )
        )

    # Update state: append the new role to host.role_names
    new_role_names = (*host.role_names, config.role_name)
    updated_host = replace(host, role_names=new_role_names)
    state.hosts[config.hostname] = updated_host

    match state_module.save(ctx.ssm, ctx.s3, state):
        case Err() as e:
            return e
        case Ok(_):
            pass

    # Read existing SOPS file, append the new profile, write back
    try:
        decrypted = decrypt_file(sops_path)
        secrets = parse_secrets_yaml(decrypted)
        new_profile = SopsProfile(
            role_name=config.role_name,
            profile_arn=str(role.profile_arn),
            role_arn=str(role.role_arn),
        )
        updated_secrets = replace(secrets, profiles=(*secrets.profiles, new_profile))
        yaml_content = create_secrets_yaml(
            hostname=config.hostname, secrets=updated_secrets
        )
        write_and_encrypt(yaml_content, sops_path)
    except (RuntimeError, ValueError) as e:
        return Err(SOPSEncryptError(sops_path, str(e)))

    return Ok(
        AddRoleResult(
            hostname=config.hostname,
            role_name=config.role_name,
            already_present=False,
            sops_file_path=sops_path,
            updated_role_names=new_role_names,
        )
    )


def remove_role(
    ctx: AwsContext, config: RemoveRoleConfig
) -> Result[RemoveRoleResult, RemoveRoleError]:
    """Detach a role from an existing host.

    Does NOT destroy the cert or host stack. Updates state and rewrites
    the SOPS file without the removed profile.

    Preconditions:
        - Namespace initialised.
        - Host exists.
        - Role is attached (if not, returns already_absent=True).
        - At least one role remains after removal. To remove a host
          entirely use `iam-ra host offboard` instead.

    Idempotent: removing a role that isn't attached returns Ok with
    already_absent=True and does not rewrite the SOPS file.
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

    # Host must exist
    if config.hostname not in state.hosts:
        return Err(HostNotFoundError(config.namespace, config.hostname))
    host = state.hosts[config.hostname]

    # Resolve SOPS path up-front
    match _resolve_sops_path(config.hostname, config.sops_path):
        case Err(e):
            return Err(e)
        case Ok(sops_path):
            pass

    # Idempotency: role not attached -> no-op success
    if config.role_name not in host.role_names:
        return Ok(
            RemoveRoleResult(
                hostname=config.hostname,
                role_name=config.role_name,
                already_absent=True,
                sops_file_path=sops_path,
                updated_role_names=host.role_names,
            )
        )

    # Can't remove the last role - would leave the host useless
    if len(host.role_names) == 1:
        return Err(
            CannotRemoveLastRoleError(
                namespace=config.namespace,
                hostname=config.hostname,
                role_name=config.role_name,
            )
        )

    # Update state: drop the role
    new_role_names = tuple(r for r in host.role_names if r != config.role_name)
    updated_host = replace(host, role_names=new_role_names)
    state.hosts[config.hostname] = updated_host

    match state_module.save(ctx.ssm, ctx.s3, state):
        case Err() as e:
            return e
        case Ok(_):
            pass

    # Read SOPS, drop the profile entry, write back
    try:
        decrypted = decrypt_file(sops_path)
        secrets = parse_secrets_yaml(decrypted)
        remaining = tuple(p for p in secrets.profiles if p.role_name != config.role_name)
        updated_secrets = replace(secrets, profiles=remaining)
        yaml_content = create_secrets_yaml(
            hostname=config.hostname, secrets=updated_secrets
        )
        write_and_encrypt(yaml_content, sops_path)
    except (RuntimeError, ValueError) as e:
        return Err(SOPSEncryptError(sops_path, str(e)))

    return Ok(
        RemoveRoleResult(
            hostname=config.hostname,
            role_name=config.role_name,
            already_absent=False,
            sops_file_path=sops_path,
            updated_role_names=new_role_names,
        )
    )


# =============================================================================
# rotate_cert: regenerate cert under the host's existing scope
# =============================================================================


@dataclass(frozen=True)
class RotateCertConfig:
    """Configuration for rotate_cert workflow."""

    namespace: str
    hostname: str
    validity_days: int = 365
    sops_path: Path | None = None


@dataclass(frozen=True)
class RotateCertResult:
    """Result of a successful cert rotation."""

    hostname: str
    scope: str
    sops_file_path: Path
    # Role list is not changed by rotation, but returning it makes the
    # output self-describing for JSON consumers.
    role_names: tuple[str, ...]


def _issue_new_host_cert(
    ctx: AwsContext,
    namespace: str,
    hostname: str,
    scope_ca: CA,
    scope: str,
    bucket_name: str,
    validity_days: int,
) -> Result[tuple[str, str], RotateCertError]:
    """Issue a new cert+key for a host under the given scope's CA.

    Returns (certificate_pem, private_key_pem). Does NOT upload to S3 or
    touch Secrets Manager - that's the caller's job, because the semantics
    differ between initial onboarding (upload + CFN-create secrets) and
    rotation (update existing secrets by ARN).
    """
    # Avoid circular-import issues with operations/ca by importing here.
    from iam_ra_cli.lib import crypto
    from iam_ra_cli.lib.storage.s3 import read_object
    from iam_ra_cli.operations.ca import _ca_cert_s3_key, _ca_key_local_path

    match scope_ca.mode:
        case CAMode.SELF_SIGNED:
            # Load CA cert from S3
            ca_cert_key = _ca_cert_s3_key(namespace, scope)
            match read_object(ctx.s3, bucket_name, ca_cert_key):
                case Err(_):
                    return Err(CACertNotFoundError(bucket_name, ca_cert_key))
                case Ok(ca_cert_pem):
                    pass

            # Load CA private key from local
            ca_key_path = _ca_key_local_path(namespace, scope)
            if not ca_key_path.exists():
                return Err(CAKeyNotFoundError(ca_key_path))
            ca_key_pem = ca_key_path.read_text()

            kp = crypto.generate_host_cert(
                hostname=hostname,
                ca_cert_pem=ca_cert_pem,
                ca_key_pem=ca_key_pem,
                validity_days=validity_days,
            )
            return Ok((kp.certificate, kp.private_key))

        case CAMode.PCA_NEW | CAMode.PCA_EXISTING:
            # PCA path: CSR -> IssueCertificate -> GetCertificate
            # Imported here to match the local-import style of the
            # SELF_SIGNED branch above (and to avoid pulling botocore into
            # every module that loads workflows.host).
            from botocore.exceptions import ClientError, WaiterError

            from iam_ra_cli.operations.host import PCA_CLIENT_AUTH_TEMPLATE_ARN

            assert scope_ca.pca_arn is not None
            pca_arn = str(scope_ca.pca_arn)

            # Generate keypair + CSR
            host_kc = crypto.generate_host_keypair_and_csr(hostname=hostname)

            # Describe PCA to check status + get signing algorithm
            try:
                desc = ctx.acm_pca.describe_certificate_authority(
                    CertificateAuthorityArn=pca_arn
                )
            except ClientError as e:
                return Err(PCADescribeError(pca_arn, str(e)))

            ca_info = desc["CertificateAuthority"]
            status = ca_info.get("Status", "UNKNOWN")
            if status != "ACTIVE":
                return Err(PCANotActiveError(pca_arn, status))
            signing_algorithm = ca_info["CertificateAuthorityConfiguration"][
                "SigningAlgorithm"
            ]

            # Issue the certificate
            try:
                issue = ctx.acm_pca.issue_certificate(
                    CertificateAuthorityArn=pca_arn,
                    Csr=host_kc.csr_pem.encode("utf-8"),
                    SigningAlgorithm=signing_algorithm,
                    Validity={"Value": validity_days, "Type": "DAYS"},
                    TemplateArn=PCA_CLIENT_AUTH_TEMPLATE_ARN,
                )
            except ClientError as e:
                return Err(PCAIssueCertError(pca_arn, str(e)))

            cert_arn = issue["CertificateArn"]

            # Wait for issuance
            waiter = ctx.acm_pca.get_waiter("certificate_issued")
            try:
                waiter.wait(
                    CertificateAuthorityArn=pca_arn,
                    CertificateArn=cert_arn,
                    WaiterConfig={"Delay": 2, "MaxAttempts": 60},
                )
            except WaiterError:
                return Err(PCATimeoutError(pca_arn, cert_arn))

            # Retrieve the signed certificate
            try:
                got = ctx.acm_pca.get_certificate(
                    CertificateAuthorityArn=pca_arn,
                    CertificateArn=cert_arn,
                )
            except ClientError as e:
                return Err(PCAGetCertError(pca_arn, cert_arn, str(e)))

            return Ok((got["Certificate"], host_kc.private_key_pem))


def rotate_cert(
    ctx: AwsContext, config: RotateCertConfig
) -> Result[RotateCertResult, RotateCertError]:
    """Rotate a host's cert without changing its roles or stack.

    Generates a new host keypair under the host's existing scope, updates
    the Secrets Manager secrets in place (same ARNs, new values - creates
    a new version with prior versions retained by AWS), and rewrites the
    SOPS file with the new cert + key while preserving all existing
    profile entries.

    Preconditions:
        - Namespace initialised.
        - Host exists.
        - Scope's CA material is available:
            - self-signed: CA cert in S3 and CA private key on disk.
            - PCA: the PCA must be in ACTIVE status.

    Does NOT touch CloudFormation - the host stack is untouched. Roles
    attached to the host are preserved exactly.
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

    # Host must exist
    if config.hostname not in state.hosts:
        return Err(HostNotFoundError(config.namespace, config.hostname))
    host = state.hosts[config.hostname]

    # Scope's CA must exist
    if host.scope not in state.cas:
        return Err(CAScopeNotFoundError(config.namespace, host.scope))
    scope_ca = state.cas[host.scope]

    # Resolve SOPS path up-front
    match _resolve_sops_path(config.hostname, config.sops_path):
        case Err(e):
            return Err(e)
        case Ok(sops_path):
            pass

    bucket_name = state.init.bucket_arn.resource_id

    # Issue new cert + key under the host's existing scope
    match _issue_new_host_cert(
        ctx,
        config.namespace,
        config.hostname,
        scope_ca,
        host.scope,
        bucket_name,
        config.validity_days,
    ):
        case Err() as e:
            return e
        case Ok(pair):
            new_cert_pem, new_key_pem = pair

    # Update Secrets Manager: new version, same ARN. moto and AWS both
    # accept SecretId as ARN or name.
    from botocore.exceptions import ClientError

    try:
        ctx.secrets.put_secret_value(
            SecretId=str(host.certificate_secret_arn),
            SecretString=new_cert_pem,
        )
        ctx.secrets.put_secret_value(
            SecretId=str(host.private_key_secret_arn),
            SecretString=new_key_pem,
        )
    except ClientError as e:
        return Err(
            SecretsManagerReadError(
                str(host.certificate_secret_arn),
                f"put_secret_value failed: {e}",
            )
        )

    # Rewrite SOPS file with new cert + key, preserving all existing
    # profiles (and the trust_anchor_arn, account_id, region fields).
    try:
        decrypted = decrypt_file(sops_path)
        secrets = parse_secrets_yaml(decrypted)
        updated_secrets = replace(
            secrets,
            certificate=new_cert_pem,
            private_key=new_key_pem,
        )
        yaml_content = create_secrets_yaml(
            hostname=config.hostname, secrets=updated_secrets
        )
        write_and_encrypt(yaml_content, sops_path)
    except (RuntimeError, ValueError) as e:
        return Err(SOPSEncryptError(sops_path, str(e)))

    return Ok(
        RotateCertResult(
            hostname=config.hostname,
            scope=host.scope,
            sops_file_path=sops_path,
            role_names=host.role_names,
        )
    )
