"""Init workflow - initialize IAM Roles Anywhere infrastructure."""

from dataclasses import dataclass

from iam_ra_cli import __version__
from iam_ra_cli.lib import paths
from iam_ra_cli.lib import state as state_module
from iam_ra_cli.lib.aws import AwsContext
from iam_ra_cli.lib.errors import CAError, StackDeployError, StateSaveError
from iam_ra_cli.lib.result import Err, Ok, Result
from iam_ra_cli.models import CA, CAMode, Init, State
from iam_ra_cli.operations.ca import (
    attach_existing_pca,
    create_pca_ca,
    create_self_signed_ca,
)
from iam_ra_cli.operations.infra import deploy_init

type InitError = StackDeployError | CAError | StateSaveError


@dataclass(frozen=True)
class InitConfig:
    """Configuration for init workflow."""

    namespace: str
    ca_mode: CAMode
    pca_arn: str | None = None  # Required for PCA_EXISTING
    ca_validity_years: int = 10


def init(ctx: AwsContext, config: InitConfig) -> Result[State, InitError]:
    """Initialize IAM Roles Anywhere infrastructure.

    1. Ensure local directories exist
    2. Deploy init stack (S3, KMS, Lambdas)
    3. Deploy CA stack based on mode
    4. Save and return state
    """
    # Ensure local directories exist
    paths.config_dir().mkdir(parents=True, exist_ok=True)
    paths.data_dir().mkdir(parents=True, exist_ok=True)

    # Step 1: Deploy init stack
    match deploy_init(ctx, config.namespace):
        case Err() as e:
            return e
        case Ok(init_result):
            pass

    # Build initial state
    new_state = State(
        namespace=config.namespace,
        region=ctx.region,
        version=__version__,
        init=Init(
            stack_name=init_result.stack_name,
            bucket_arn=init_result.bucket_arn,
            kms_key_arn=init_result.kms_key_arn,
        ),
    )

    # Step 2: Deploy CA stack based on mode
    match config.ca_mode:
        case CAMode.SELF_SIGNED:
            match create_self_signed_ca(
                ctx,
                config.namespace,
                init_result.bucket_name,
                config.ca_validity_years,
            ):
                case Err() as e:
                    return e
                case Ok(self_signed_result):
                    new_state.ca = CA(
                        stack_name=self_signed_result.stack_name,
                        mode=CAMode.SELF_SIGNED,
                        trust_anchor_arn=self_signed_result.trust_anchor_arn,
                    )

        case CAMode.PCA_NEW:
            match create_pca_ca(ctx, config.namespace, validity_years=config.ca_validity_years):
                case Err() as e:
                    return e
                case Ok(pca_new_result):
                    new_state.ca = CA(
                        stack_name=pca_new_result.stack_name,
                        mode=CAMode.PCA_NEW,
                        trust_anchor_arn=pca_new_result.trust_anchor_arn,
                        pca_arn=pca_new_result.pca_arn,
                    )

        case CAMode.PCA_EXISTING:
            if config.pca_arn is None:
                return Err(
                    StackDeployError("", "INVALID_CONFIG", "pca_arn required for PCA_EXISTING mode")
                )
            match attach_existing_pca(ctx, config.namespace, config.pca_arn):
                case Err() as e:
                    return e
                case Ok(pca_existing_result):
                    new_state.ca = CA(
                        stack_name=pca_existing_result.stack_name,
                        mode=CAMode.PCA_EXISTING,
                        trust_anchor_arn=pca_existing_result.trust_anchor_arn,
                        pca_arn=pca_existing_result.pca_arn,
                    )

    # Step 3: Save state
    match state_module.save(ctx.ssm, ctx.s3, new_state):
        case Err() as e:
            return e
        case Ok(_):
            pass

    return Ok(new_state)
