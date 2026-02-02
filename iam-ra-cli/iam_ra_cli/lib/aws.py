"""AWS client helpers for IAM Roles Anywhere CLI."""

import boto3
from botocore.exceptions import ClientError
from typing import Optional


def get_session(region: str, profile: Optional[str] = None) -> boto3.Session:
    """Create a boto3 session with optional profile."""
    if profile:
        return boto3.Session(region_name=region, profile_name=profile)
    return boto3.Session(region_name=region)


def get_secret(
    secret_name: str,
    region: str,
    profile: Optional[str] = None,
) -> str:
    """
    Retrieve a secret value from AWS Secrets Manager.

    Args:
        secret_name: Name or ARN of the secret
        region: AWS region
        profile: Optional AWS profile name

    Returns:
        The secret string value

    Raises:
        ClientError: If the secret cannot be retrieved
    """
    session = get_session(region, profile)
    client = session.client("secretsmanager")

    response = client.get_secret_value(SecretId=secret_name)
    return response["SecretString"]


def get_parameter(
    parameter_name: str,
    region: str,
    profile: Optional[str] = None,
    decrypt: bool = True,
) -> str:
    """
    Retrieve a parameter value from AWS Systems Manager Parameter Store.

    Args:
        parameter_name: Name of the parameter
        region: AWS region
        profile: Optional AWS profile name
        decrypt: Whether to decrypt SecureString parameters

    Returns:
        The parameter value

    Raises:
        ClientError: If the parameter cannot be retrieved
    """
    session = get_session(region, profile)
    client = session.client("ssm")

    response = client.get_parameter(Name=parameter_name, WithDecryption=decrypt)
    return response["Parameter"]["Value"]


def get_parameters_by_path(
    path: str,
    region: str,
    profile: Optional[str] = None,
    recursive: bool = True,
) -> dict[str, str]:
    """
    Retrieve all parameters under a path from SSM Parameter Store.

    Args:
        path: Parameter path prefix (e.g., /iam-ra/hosts/lnv-01)
        region: AWS region
        profile: Optional AWS profile name
        recursive: Whether to retrieve parameters recursively

    Returns:
        Dictionary mapping parameter names to values
    """
    session = get_session(region, profile)
    client = session.client("ssm")

    params = {}
    paginator = client.get_paginator("get_parameters_by_path")

    for page in paginator.paginate(Path=path, Recursive=recursive, WithDecryption=True):
        for param in page["Parameters"]:
            params[param["Name"]] = param["Value"]

    return params
