"""Role operations - IAM Role stack deployment."""

from dataclasses import dataclass

from iam_ra_cli.lib.aws import AwsContext
from iam_ra_cli.lib.cfn import delete_stack, deploy_stack
from iam_ra_cli.lib.errors import StackDeleteError, StackDeployError
from iam_ra_cli.lib.result import Err, Ok, Result
from iam_ra_cli.lib.templates import get_template_path
from iam_ra_cli.models import Arn

ROLE_TEMPLATE = "role.yaml"


def _stack_name(namespace: str, role_name: str) -> str:
    return f"iam-ra-{namespace}-role-{role_name}"


def _load_template(name: str) -> str:
    path = get_template_path(name)
    return path.read_text()


@dataclass(frozen=True, slots=True)
class RoleResult:
    """Result of creating a role."""

    stack_name: str
    role_arn: Arn
    profile_arn: Arn
    policies: tuple[Arn, ...]


def create_role(
    ctx: AwsContext,
    namespace: str,
    name: str,
    policies: list[str] | None = None,
    session_duration: int = 3600,
    *,
    trust_anchor_arn: str,
    scope: str = "default",
) -> Result[RoleResult, StackDeployError]:
    """Create an IAM role with Roles Anywhere profile.

    Args:
        ctx: AWS context
        namespace: Namespace identifier
        name: Role name
        policies: List of managed policy ARNs to attach
        session_duration: Session duration in seconds (900-43200)
        trust_anchor_arn: Trust Anchor ARN for the role's scope
        scope: CA scope this role belongs to
    """
    stack_name = _stack_name(namespace, name)
    template = _load_template(ROLE_TEMPLATE)

    params: dict[str, str] = {
        "Namespace": namespace,
        "RoleName": name,
        "TrustAnchorArn": trust_anchor_arn,
        "SessionDuration": str(session_duration),
    }
    if policies:
        params["PolicyArns"] = ",".join(policies)

    match deploy_stack(
        ctx.cfn,
        stack_name=stack_name,
        template_body=template,
        parameters=params,
        tags={
            "iam-ra:namespace": namespace,
            "iam-ra:role": name,
            "iam-ra:scope": scope,
        },
        capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    ):
        case Err() as e:
            return e
        case Ok(outputs):
            return Ok(
                RoleResult(
                    stack_name=stack_name,
                    role_arn=Arn(outputs["RoleArn"]),
                    profile_arn=Arn(outputs["ProfileArn"]),
                    policies=tuple(Arn(p) for p in (policies or [])),
                )
            )


def delete_role(ctx: AwsContext, stack_name: str) -> Result[None, StackDeleteError]:
    """Delete a role stack."""
    return delete_stack(ctx.cfn, stack_name)
