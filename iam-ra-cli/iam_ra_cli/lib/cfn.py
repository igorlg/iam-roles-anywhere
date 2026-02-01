"""CloudFormation helpers for IAM Roles Anywhere CLI."""

import boto3
from botocore.exceptions import ClientError
from typing import Optional
import time


def get_stack_outputs(
    stack_name: str,
    region: str,
    profile: Optional[str] = None,
) -> dict[str, str]:
    """
    Get outputs from a CloudFormation stack.

    Args:
        stack_name: Name of the CloudFormation stack
        region: AWS region
        profile: Optional AWS profile name

    Returns:
        Dictionary mapping output keys to values

    Raises:
        ClientError: If the stack doesn't exist or can't be described
    """
    session = (
        boto3.Session(region_name=region, profile_name=profile)
        if profile
        else boto3.Session(region_name=region)
    )
    client = session.client("cloudformation")

    response = client.describe_stacks(StackName=stack_name)

    if not response["Stacks"]:
        raise ValueError(f"Stack '{stack_name}' not found")

    stack = response["Stacks"][0]
    outputs = {}

    for output in stack.get("Outputs", []):
        outputs[output["OutputKey"]] = output["OutputValue"]

    return outputs


def stack_exists(
    stack_name: str,
    region: str,
    profile: Optional[str] = None,
) -> bool:
    """
    Check if a CloudFormation stack exists.

    Args:
        stack_name: Name of the CloudFormation stack
        region: AWS region
        profile: Optional AWS profile name

    Returns:
        True if the stack exists, False otherwise
    """
    session = (
        boto3.Session(region_name=region, profile_name=profile)
        if profile
        else boto3.Session(region_name=region)
    )
    client = session.client("cloudformation")

    try:
        response = client.describe_stacks(StackName=stack_name)
        # Check if stack is in a "deleted" state
        if response["Stacks"]:
            status = response["Stacks"][0]["StackStatus"]
            return status != "DELETE_COMPLETE"
        return False
    except ClientError as e:
        if "does not exist" in str(e):
            return False
        raise


def get_stack_status(
    stack_name: str,
    region: str,
    profile: Optional[str] = None,
) -> Optional[str]:
    """
    Get the current status of a CloudFormation stack.

    Args:
        stack_name: Name of the CloudFormation stack
        region: AWS region
        profile: Optional AWS profile name

    Returns:
        Stack status string or None if stack doesn't exist
    """
    session = (
        boto3.Session(region_name=region, profile_name=profile)
        if profile
        else boto3.Session(region_name=region)
    )
    client = session.client("cloudformation")

    try:
        response = client.describe_stacks(StackName=stack_name)
        if response["Stacks"]:
            return response["Stacks"][0]["StackStatus"]
        return None
    except ClientError as e:
        if "does not exist" in str(e):
            return None
        raise
