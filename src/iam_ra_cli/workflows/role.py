"""Role workflows - create, delete, list roles."""

from iam_ra_cli.lib import state as state_module
from iam_ra_cli.lib.aws import AwsContext
from iam_ra_cli.lib.errors import (
    NotInitializedError,
    RoleInUseError,
    RoleNotFoundError,
    StackDeleteError,
    StackDeployError,
    StateLoadError,
    StateSaveError,
)
from iam_ra_cli.lib.result import Err, Ok, Result
from iam_ra_cli.models import Role
from iam_ra_cli.operations.role import create_role as create_role_op
from iam_ra_cli.operations.role import delete_role as delete_role_op

type CreateRoleError = NotInitializedError | StackDeployError | StateSaveError | StateLoadError
type DeleteRoleError = (
    NotInitializedError
    | RoleNotFoundError
    | RoleInUseError
    | StackDeleteError
    | StateSaveError
    | StateLoadError
)
type ListRolesError = NotInitializedError | StateLoadError


def create_role(
    ctx: AwsContext,
    namespace: str,
    name: str,
    policies: list[str] | None = None,
    session_duration: int = 3600,
) -> Result[Role, CreateRoleError]:
    """Create or update an IAM role with Roles Anywhere profile.

    Idempotent: if the role already exists, re-deploys the CFN stack
    to ensure the current policies are attached. CloudFormation handles
    the diff -- same config is a no-op, different policies triggers an update.

    1. Load state, validate initialized
    2. Deploy role stack (create or update)
    3. Update state
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

    # Deploy role stack (CFN handles create vs update)
    match create_role_op(ctx, namespace, name, policies, session_duration):
        case Err() as e:
            return e
        case Ok(role_result):
            pass

    # Create Role model
    new_role = Role(
        stack_name=role_result.stack_name,
        role_arn=role_result.role_arn,
        profile_arn=role_result.profile_arn,
        policies=role_result.policies,
    )

    # Update state (always -- policies may have changed)
    state.roles[name] = new_role
    match state_module.save(ctx.ssm, ctx.s3, state):
        case Err() as e:
            return e
        case Ok(_):
            pass

    return Ok(new_role)


def delete_role(
    ctx: AwsContext,
    namespace: str,
    name: str,
    force: bool = False,
) -> Result[None, DeleteRoleError]:
    """Delete an IAM role.

    1. Load state
    2. Check role exists
    3. Check no hosts are using the role (unless force)
    4. Delete role stack
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

    # Check role exists
    if name not in state.roles:
        return Err(RoleNotFoundError(namespace, name))

    # Check no hosts are using this role
    if not force:
        hosts_using = tuple(h for h, host in state.hosts.items() if host.role_name == name)
        if hosts_using:
            return Err(RoleInUseError(name, hosts_using))

    role = state.roles[name]

    # Delete role stack
    match delete_role_op(ctx, role.stack_name):
        case Err() as e:
            return e
        case Ok(_):
            pass

    # Update state
    del state.roles[name]
    match state_module.save(ctx.ssm, ctx.s3, state):
        case Err() as e:
            return e
        case Ok(_):
            pass

    return Ok(None)


def list_roles(ctx: AwsContext, namespace: str) -> Result[dict[str, Role], ListRolesError]:
    """List all roles in a namespace."""
    match state_module.load(ctx.ssm, ctx.s3, namespace):
        case Err(e):
            return Err(e)
        case Ok(None):
            return Err(NotInitializedError(namespace))
        case Ok(state):
            return Ok(state.roles)
