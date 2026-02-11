"""S3 storage operations.

Low-level helpers that work with S3 client.
Returns Result types for error handling.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from botocore.exceptions import ClientError

from iam_ra_cli.lib.errors import S3ReadError, S3WriteError
from iam_ra_cli.lib.result import Err, Ok, Result

if TYPE_CHECKING:
    from mypy_boto3_s3 import S3Client


def read_object(s3: S3Client, bucket: str, key: str) -> Result[str, S3ReadError]:
    """Read object from S3 as string."""
    try:
        response = s3.get_object(Bucket=bucket, Key=key)
        return Ok(response["Body"].read().decode("utf-8"))
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchKey":
            return Err(S3ReadError(bucket, key, "Object not found"))
        return Err(S3ReadError(bucket, key, str(e)))


def write_object(s3: S3Client, bucket: str, key: str, data: str) -> Result[None, S3WriteError]:
    """Write string data to S3."""
    try:
        s3.put_object(Bucket=bucket, Key=key, Body=data.encode("utf-8"))
        return Ok(None)
    except ClientError as e:
        return Err(S3WriteError(bucket, key, str(e)))


def delete_object(s3: S3Client, bucket: str, key: str) -> Result[None, S3WriteError]:
    """Delete object from S3."""
    try:
        s3.delete_object(Bucket=bucket, Key=key)
        return Ok(None)
    except ClientError as e:
        return Err(S3WriteError(bucket, key, str(e)))


def object_exists(s3: S3Client, bucket: str, key: str) -> bool:
    """Check if object exists in S3."""
    try:
        s3.head_object(Bucket=bucket, Key=key)
        return True
    except ClientError:
        return False
