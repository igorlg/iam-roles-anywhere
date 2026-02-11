"""AWS session and client management.

AwsContext is created once at CLI entry and passed to all operations.
Uses cached_property for lazy client initialization.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import cached_property
from typing import TYPE_CHECKING

import boto3

if TYPE_CHECKING:
    from mypy_boto3_cloudformation import CloudFormationClient
    from mypy_boto3_s3 import S3Client
    from mypy_boto3_secretsmanager import SecretsManagerClient
    from mypy_boto3_ssm import SSMClient
    from mypy_boto3_sts import STSClient


@dataclass
class AwsContext:
    """AWS session and clients. Created once at CLI entry.

    Clients are lazily initialized on first access via cached_property.

    Example:
        ctx = AwsContext(region="ap-southeast-2", profile="dev")
        ctx.cfn.describe_stacks(...)  # CloudFormation client
        ctx.s3.get_object(...)        # S3 client
    """

    region: str
    profile: str | None = None

    @cached_property
    def session(self) -> boto3.Session:
        """Boto3 session configured with region and profile."""
        return boto3.Session(region_name=self.region, profile_name=self.profile)

    @cached_property
    def cfn(self) -> CloudFormationClient:
        """CloudFormation client."""
        return self.session.client("cloudformation")

    @cached_property
    def s3(self) -> S3Client:
        """S3 client."""
        return self.session.client("s3")

    @cached_property
    def ssm(self) -> SSMClient:
        """SSM Parameter Store client."""
        return self.session.client("ssm")

    @cached_property
    def secrets(self) -> SecretsManagerClient:
        """Secrets Manager client."""
        return self.session.client("secretsmanager")

    @cached_property
    def sts(self) -> STSClient:
        """STS client."""
        return self.session.client("sts")

    @cached_property
    def account_id(self) -> str:
        """AWS account ID for the current session."""
        return self.sts.get_caller_identity()["Account"]
