"""CloudFormation operations.

Low-level helpers that work with CloudFormation client.
Returns Result types for error handling.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from botocore.exceptions import ClientError

from iam_ra_cli.lib.errors import StackDeleteError, StackDeployError
from iam_ra_cli.lib.result import Err, Ok, Result

if TYPE_CHECKING:
    from mypy_boto3_cloudformation import CloudFormationClient


def stack_exists(cfn: CloudFormationClient, stack_name: str) -> bool:
    """Check if stack exists (and is not deleted)."""
    try:
        response = cfn.describe_stacks(StackName=stack_name)
        if response["Stacks"]:
            status = response["Stacks"][0]["StackStatus"]
            return status != "DELETE_COMPLETE"
        return False
    except ClientError as e:
        if "does not exist" in str(e):
            return False
        raise


def get_stack_status(cfn: CloudFormationClient, stack_name: str) -> str | None:
    """Get stack status, or None if doesn't exist."""
    try:
        response = cfn.describe_stacks(StackName=stack_name)
        if response["Stacks"]:
            return response["Stacks"][0]["StackStatus"]
        return None
    except ClientError as e:
        if "does not exist" in str(e):
            return None
        raise


def get_stack_outputs(cfn: CloudFormationClient, stack_name: str) -> dict[str, str]:
    """Get stack outputs as dict."""
    response = cfn.describe_stacks(StackName=stack_name)
    if not response["Stacks"]:
        return {}

    outputs = {}
    for output in response["Stacks"][0].get("Outputs", []):
        outputs[output["OutputKey"]] = output["OutputValue"]
    return outputs


def deploy_stack(
    cfn: CloudFormationClient,
    stack_name: str,
    template_body: str,
    parameters: dict[str, str] | None = None,
    tags: dict[str, str] | None = None,
    capabilities: list[str] | None = None,
    timeout_seconds: int = 600,
) -> Result[dict[str, str], StackDeployError]:
    """Deploy stack (create or update). Returns outputs on success."""
    params_list = [{"ParameterKey": k, "ParameterValue": v} for k, v in (parameters or {}).items()]
    tags_list = [{"Key": k, "Value": v} for k, v in (tags or {}).items()]
    caps = capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM", "CAPABILITY_AUTO_EXPAND"]

    kwargs: dict[str, Any] = {
        "StackName": stack_name,
        "TemplateBody": template_body,
        "Capabilities": caps,
    }
    if params_list:
        kwargs["Parameters"] = params_list
    if tags_list:
        kwargs["Tags"] = tags_list

    try:
        if stack_exists(cfn, stack_name):
            cfn.update_stack(**kwargs)
            target_status = "UPDATE_COMPLETE"
        else:
            cfn.create_stack(**kwargs)
            target_status = "CREATE_COMPLETE"
    except ClientError as e:
        # "No updates are to be performed" is not an error
        if "No updates are to be performed" in str(e):
            return Ok(get_stack_outputs(cfn, stack_name))
        return Err(StackDeployError(stack_name, "FAILED", str(e)))

    # Wait for completion
    result = wait_for_stack(cfn, stack_name, target_status, timeout_seconds)
    match result:
        case Ok(_):
            return Ok(get_stack_outputs(cfn, stack_name))
        case Err(e):
            return Err(StackDeployError(stack_name, e.status, e.reason))


def delete_stack(
    cfn: CloudFormationClient,
    stack_name: str,
    timeout_seconds: int = 600,
) -> Result[None, StackDeleteError]:
    """Delete stack and wait for completion."""
    if not stack_exists(cfn, stack_name):
        return Ok(None)

    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as e:
        return Err(StackDeleteError(stack_name, "DELETE_FAILED", str(e)))

    result = wait_for_stack(cfn, stack_name, "DELETE_COMPLETE", timeout_seconds)
    match result:
        case Ok(_):
            return Ok(None)
        case Err(e):
            return Err(StackDeleteError(stack_name, e.status, e.reason))


def wait_for_stack(
    cfn: CloudFormationClient,
    stack_name: str,
    target_status: str,
    timeout_seconds: int = 600,
    poll_interval: int = 5,
) -> Result[None, StackDeployError]:
    """Wait for stack to reach target status."""
    failed_states = {
        "CREATE_FAILED",
        "ROLLBACK_COMPLETE",
        "ROLLBACK_FAILED",
        "UPDATE_ROLLBACK_COMPLETE",
        "UPDATE_ROLLBACK_FAILED",
        "DELETE_FAILED",
    }

    elapsed = 0
    while elapsed < timeout_seconds:
        status = get_stack_status(cfn, stack_name)

        # DELETE_COMPLETE means stack is gone
        if target_status == "DELETE_COMPLETE" and status is None:
            return Ok(None)

        if status == target_status:
            return Ok(None)

        if status in failed_states:
            # Try to get failure reason
            reason = _get_stack_failure_reason(cfn, stack_name)
            return Err(StackDeployError(stack_name, status, reason))

        time.sleep(poll_interval)
        elapsed += poll_interval

    return Err(
        StackDeployError(
            stack_name, "TIMEOUT", f"Did not reach {target_status} within {timeout_seconds}s"
        )
    )


def _get_stack_failure_reason(cfn: CloudFormationClient, stack_name: str) -> str:
    """Try to extract failure reason from stack events."""
    try:
        response = cfn.describe_stack_events(StackName=stack_name)
        for event in response.get("StackEvents", []):
            status = event.get("ResourceStatus", "")
            if "FAILED" in status and event.get("ResourceStatusReason"):
                return event["ResourceStatusReason"]
        return "Unknown failure reason"
    except ClientError:
        return "Could not retrieve failure reason"
