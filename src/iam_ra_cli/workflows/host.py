"""Host workflows - onboard, offboard, list hosts."""

from dataclasses import dataclass
from pathlib import Path

from iam_ra_cli.lib import state as state_module
from iam_ra_cli.lib.aws import AwsContext
from iam_ra_cli.lib.errors import (
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
from iam_ra_cli.models import CAMode, Host
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
    """Configuration for onboard workflow."""

    namespace: str
    hostname: str
    role_name: str
    validity_days: int = 365
    create_sops: bool = True
    sops_output_path: Path | None = None
    overwrite: bool = False


@dataclass(frozen=True)
class OnboardResult:
    """Result of onboard workflow."""

    host: Host
    secrets_file: SecretsFileResult | None


def onboard(ctx: AwsContext, config: OnboardConfig) -> Result[OnboardResult, OnboardError]:
    """Onboard a host to IAM Roles Anywhere.

    1. Load state, validate initialized
    2. Validate role exists
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
    assert state.ca is not None

    # Validate role exists
    if config.role_name not in state.roles:
        return Err(RoleNotFoundError(config.namespace, config.role_name))

    role = state.roles[config.role_name]

    # Check host doesn't already exist
    if config.hostname in state.hosts and not config.overwrite:
        return Err(HostAlreadyExistsError(config.namespace, config.hostname))

    bucket_name = state.init.bucket_arn.resource_id

    # Generate cert and deploy host stack based on CA mode
    match state.ca.mode:
        case CAMode.SELF_SIGNED:
            match onboard_host_self_signed(
                ctx,
                config.namespace,
                config.hostname,
                bucket_name,
                config.validity_days,
            ):
                case Err() as e:
                    return e
                case Ok(host_result):
                    pass

        case CAMode.PCA_NEW | CAMode.PCA_EXISTING:
            assert state.ca.pca_arn is not None
            match onboard_host_pca(
                ctx,
                config.namespace,
                config.hostname,
                str(state.ca.pca_arn),
                bucket_name,
                config.validity_days,
            ):
                case Err() as e:
                    return e
                case Ok(host_result):
                    pass

    # Create Host model
    new_host = Host(
        stack_name=host_result.stack_name,
        hostname=config.hostname,
        role_name=config.role_name,
        certificate_secret_arn=host_result.certificate_secret_arn,
        private_key_secret_arn=host_result.private_key_secret_arn,
    )

    # Update state
    state.hosts[config.hostname] = new_host
    match state_module.save(ctx.ssm, ctx.s3, state):
        case Err() as e:
            return e
        case Ok(_):
            pass

    # Create SOPS secrets file if requested
    secrets_result: SecretsFileResult | None = None
    if config.create_sops:
        match create_secrets_file(
            ctx,
            hostname=config.hostname,
            certificate_secret_arn=str(host_result.certificate_secret_arn),
            private_key_secret_arn=str(host_result.private_key_secret_arn),
            trust_anchor_arn=str(state.ca.trust_anchor_arn),
            profile_arn=str(role.profile_arn),
            role_arn=str(role.role_arn),
            output_path=config.sops_output_path,
            overwrite=config.overwrite,
        ):
            case Err() as e:
                # Don't fail the whole workflow for secrets file error
                # The host is already onboarded at this point
                return e
            case Ok(result):
                secrets_result = result

    return Ok(OnboardResult(host=new_host, secrets_file=secrets_result))


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
