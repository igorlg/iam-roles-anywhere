"""Infrastructure operations - init stack deployment."""

from dataclasses import dataclass
from pathlib import Path

from iam_ra_cli.lib.aws import AwsContext
from iam_ra_cli.lib.cfn import delete_stack, deploy_stack
from iam_ra_cli.lib.errors import StackDeleteError, StackDeployError
from iam_ra_cli.lib.result import Err, Ok, Result
from iam_ra_cli.lib.templates import get_template_path
from iam_ra_cli.models import Arn

INIT_TEMPLATE = "init.yaml"


def _stack_name(namespace: str) -> str:
    return f"iam-ra-{namespace}-init"


def _load_template(name: str) -> str:
    path = get_template_path(name)
    return path.read_text()


@dataclass(frozen=True, slots=True)
class InitResult:
    """Result of deploying init stack."""

    stack_name: str
    bucket_name: str
    bucket_arn: Arn
    kms_key_arn: Arn


def deploy_init(ctx: AwsContext, namespace: str) -> Result[InitResult, StackDeployError]:
    """Deploy the init stack (S3 bucket, KMS key, Lambdas).

    This is the first stack that must be deployed before any other.
    """
    stack_name = _stack_name(namespace)
    template = _load_template(INIT_TEMPLATE)

    result = deploy_stack(
        ctx.cfn,
        stack_name=stack_name,
        template_body=template,
        parameters={"Namespace": namespace},
        tags={"iam-ra:namespace": namespace},
    )

    match result:
        case Err() as e:
            return e
        case Ok(outputs):
            return Ok(
                InitResult(
                    stack_name=stack_name,
                    bucket_name=outputs["BucketName"],
                    bucket_arn=Arn(outputs["BucketArn"]),
                    kms_key_arn=Arn(outputs["KMSKeyArn"]),
                )
            )


def delete_init(ctx: AwsContext, namespace: str) -> Result[None, StackDeleteError]:
    """Delete the init stack.

    Warning: This will also trigger bucket cleanup (all objects deleted).
    """
    stack_name = _stack_name(namespace)
    return delete_stack(ctx.cfn, stack_name)
