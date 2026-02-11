"""Destroy workflow - tear down all IAM Roles Anywhere infrastructure."""

from iam_ra_cli.lib import state as state_module
from iam_ra_cli.lib.aws import AwsContext
from iam_ra_cli.lib.errors import NotInitializedError, StackDeleteError, StateLoadError
from iam_ra_cli.lib.result import Err, Ok, Result
from iam_ra_cli.operations.ca import delete_ca
from iam_ra_cli.operations.host import offboard_host
from iam_ra_cli.operations.infra import delete_init
from iam_ra_cli.operations.role import delete_role

type DestroyError = NotInitializedError | StackDeleteError | StateLoadError


def destroy(ctx: AwsContext, namespace: str) -> Result[None, DestroyError]:
    """Destroy all IAM Roles Anywhere infrastructure for a namespace.

    Deletes in order:
    1. All host stacks
    2. All role stacks
    3. CA stack
    4. Init stack (triggers bucket cleanup)
    5. Clear local cache
    """
    # Load current state
    match state_module.load(ctx.ssm, ctx.s3, namespace):
        case Err(e):
            return Err(e)
        case Ok(None):
            return Err(NotInitializedError(namespace))
        case Ok(state):
            pass

    if not state.init:
        return Err(NotInitializedError(namespace))

    bucket_name = state.init.bucket_arn.resource_id

    # Step 1: Delete all host stacks
    for hostname, host in state.hosts.items():
        match offboard_host(ctx, host.stack_name, bucket_name, namespace, hostname):
            case Err(e):
                return Err(e)
            case Ok(_):
                pass

    # Step 2: Delete all role stacks
    for role_name, role in state.roles.items():
        match delete_role(ctx, role.stack_name):
            case Err(e):
                return Err(e)
            case Ok(_):
                pass

    # Step 3: Delete CA stack
    if state.ca:
        match delete_ca(ctx, state.ca.stack_name):
            case Err(e):
                return Err(e)
            case Ok(_):
                pass

    # Step 4: Delete init stack (this will empty and delete the bucket)
    match delete_init(ctx, namespace):
        case Err(e):
            return Err(e)
        case Ok(_):
            pass

    # Step 5: Clear local cache
    state_module.invalidate_cache(namespace)

    return Ok(None)
