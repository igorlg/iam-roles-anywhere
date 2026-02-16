"""CA workflows - setup, delete, list Certificate Authorities.

Manages per-scope CAs. Each scope gets its own CA, Trust Anchor,
S3 cert path, local key path, and CloudFormation stack.
"""

from iam_ra_cli.lib import state as state_module
from iam_ra_cli.lib.aws import AwsContext
from iam_ra_cli.lib.errors import (
    CAScopeAlreadyExistsError,
    CAScopeNotFoundError,
    CAError,
    NotInitializedError,
    StackDeleteError,
    StateLoadError,
    StateSaveError,
)
from iam_ra_cli.lib.result import Err, Ok, Result
from iam_ra_cli.models import CA, CAMode
from iam_ra_cli.operations.ca import (
    create_self_signed_ca,
    delete_ca as delete_ca_op,
)

type SetupError = (
    NotInitializedError | CAScopeAlreadyExistsError | CAError | StateLoadError | StateSaveError
)

type DeleteError = (
    NotInitializedError | CAScopeNotFoundError | StackDeleteError | StateLoadError | StateSaveError
)

type ListError = NotInitializedError | StateLoadError


def setup_ca(
    ctx: AwsContext,
    namespace: str,
    scope: str = "default",
    validity_years: int = 10,
) -> Result[CA, SetupError]:
    """Set up a new CA for a scope.

    Creates:
    - Self-signed CA certificate + private key
    - CloudFormation stack with Trust Anchor
    - State entry in cas[scope]

    Args:
        ctx: AWS context
        namespace: IAM-RA namespace
        scope: Scope name (e.g., "default", "cert-manager")
        validity_years: CA certificate validity

    Returns:
        CA configuration on success
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

    # Check scope doesn't already exist
    if scope in state.cas:
        return Err(CAScopeAlreadyExistsError(namespace, scope))

    bucket_name = state.init.bucket_arn.resource_id

    # Create CA for this scope (self-signed only for now)
    match create_self_signed_ca(
        ctx,
        namespace,
        bucket_name,
        scope=scope,
        validity_years=validity_years,
    ):
        case Err() as e:
            return e
        case Ok(result):
            pass

    ca = CA(
        stack_name=result.stack_name,
        mode=CAMode.SELF_SIGNED,
        trust_anchor_arn=result.trust_anchor_arn,
    )

    # Update state
    state.cas[scope] = ca
    match state_module.save(ctx.ssm, ctx.s3, state):
        case Err() as e:
            return e
        case Ok(_):
            pass

    return Ok(ca)


def delete_scope(
    ctx: AwsContext,
    namespace: str,
    scope: str,
) -> Result[None, DeleteError]:
    """Delete a CA scope.

    Removes:
    - CloudFormation stack (Trust Anchor)
    - State entry from cas[scope]

    Note: does NOT delete the S3 cert or local key. Those are left
    for forensics/recovery. The migrate command handles full cleanup.

    Args:
        ctx: AWS context
        namespace: IAM-RA namespace
        scope: Scope name to delete

    Returns:
        None on success
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

    # Check scope exists
    if scope not in state.cas:
        return Err(CAScopeNotFoundError(namespace, scope))

    ca = state.cas[scope]

    # Delete the CFN stack
    match delete_ca_op(ctx, ca.stack_name):
        case Err(e):
            return Err(e)
        case Ok(_):
            pass

    # Update state
    del state.cas[scope]
    match state_module.save(ctx.ssm, ctx.s3, state):
        case Err() as e:
            return e
        case Ok(_):
            pass

    return Ok(None)


def list_cas(
    ctx: AwsContext,
    namespace: str,
) -> Result[dict[str, CA], ListError]:
    """List all CA scopes.

    Args:
        ctx: AWS context
        namespace: IAM-RA namespace

    Returns:
        Dict of scope name -> CA on success
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

    return Ok(state.cas)
