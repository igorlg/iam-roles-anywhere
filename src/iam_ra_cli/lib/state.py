"""State management - load/save with caching.

Flow:
1. SSM parameter /iam-ra/<namespace>/state-location contains S3 URI
2. S3 object contains full state JSON
3. Local cache at ~/.cache/iam-ra/<namespace>/state.json
"""

import re

from botocore.exceptions import ClientError
from mypy_boto3_s3 import S3Client
from mypy_boto3_ssm import SSMClient

from iam_ra_cli.lib import paths
from iam_ra_cli.lib.errors import (
    S3ReadError,
    SSMReadError,
    SSMWriteError,
    StateLoadError,
    StateSaveError,
)
from iam_ra_cli.lib.result import Err, Ok, Result
from iam_ra_cli.lib.storage import file
from iam_ra_cli.models import State

# Cache TTL in seconds (5 minutes)
CACHE_TTL = 300

# SSM parameter paths
SSM_PREFIX = "/iam-ra/{namespace}"
SSM_STATE_LOCATION = f"{SSM_PREFIX}/state-location"


def _parse_s3_uri(uri: str) -> tuple[str, str]:
    """Parse s3://bucket/key into (bucket, key)."""
    match = re.match(r"^s3://([^/]+)/(.+)$", uri)
    if not match:
        raise ValueError(f"Invalid S3 URI: {uri}")
    return match.group(1), match.group(2)


def _get_state_location(ssm: SSMClient, namespace: str) -> Result[str, SSMReadError]:
    """Get S3 URI from SSM parameter."""
    param_name = SSM_STATE_LOCATION.format(namespace=namespace)
    try:
        response = ssm.get_parameter(Name=param_name)
        return Ok(response["Parameter"]["Value"])
    except ClientError as e:
        if e.response["Error"]["Code"] == "ParameterNotFound":
            return Err(SSMReadError(param_name, "Parameter not found"))
        return Err(SSMReadError(param_name, str(e)))


def _set_state_location(ssm: SSMClient, namespace: str, s3_uri: str) -> Result[None, SSMWriteError]:
    """Set S3 URI in SSM parameter."""
    param_name = SSM_STATE_LOCATION.format(namespace=namespace)
    try:
        ssm.put_parameter(Name=param_name, Value=s3_uri, Type="String", Overwrite=True)
        return Ok(None)
    except ClientError as e:
        return Err(SSMWriteError(param_name, str(e)))


def load(
    ssm: SSMClient,
    s3: S3Client,
    namespace: str,
    skip_cache: bool = False,
) -> Result[State | None, StateLoadError]:
    """Load state, using cache if fresh.

    Returns Ok(None) if namespace is not initialized.
    Returns Ok(State) if state was loaded successfully.
    Returns Err if there was an error loading state.
    """
    cache_path = paths.state_cache_path(namespace)

    # Check cache first (unless skipped)
    if not skip_cache and file.is_fresh(cache_path, CACHE_TTL):
        cached = file.read(cache_path)
        if cached:
            return Ok(State.from_json(cached))

    # Get S3 location from SSM
    match _get_state_location(ssm, namespace):
        case Err(SSMReadError(_, reason)) if "not found" in reason.lower():
            # Not initialized - this is OK, just return None
            return Ok(None)
        case Err(e):
            return Err(StateLoadError(namespace, e.reason))
        case Ok(s3_uri):
            pass

    # Fetch from S3
    bucket, key = _parse_s3_uri(s3_uri)
    try:
        response = s3.get_object(Bucket=bucket, Key=key)
        data = response["Body"].read().decode("utf-8")
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchKey":
            return Err(StateLoadError(namespace, f"State file not found at {s3_uri}"))
        return Err(StateLoadError(namespace, str(e)))

    state = State.from_json(data)

    # Update cache
    file.write(cache_path, data)

    return Ok(state)


def save(
    ssm: SSMClient,
    s3: S3Client,
    state: State,
) -> Result[None, StateSaveError]:
    """Save state to S3 and update cache.

    Requires state.init to be set (for bucket info).
    """
    if not state.init:
        return Err(
            StateSaveError(state.namespace, "Cannot save state without init (no bucket configured)")
        )

    bucket = state.init.bucket_arn.resource_id
    key = f"{state.namespace}/state.json"
    data = state.to_json()

    # Write to S3
    try:
        s3.put_object(Bucket=bucket, Key=key, Body=data.encode("utf-8"))
    except ClientError as e:
        return Err(StateSaveError(state.namespace, f"Failed to write to S3: {e}"))

    # Ensure SSM pointer exists
    s3_uri = f"s3://{bucket}/{key}"
    match _set_state_location(ssm, state.namespace, s3_uri):
        case Err(e):
            return Err(StateSaveError(state.namespace, f"Failed to update SSM: {e.reason}"))
        case Ok(_):
            pass

    # Update cache
    cache_path = paths.state_cache_path(state.namespace)
    file.write(cache_path, data)

    return Ok(None)


def invalidate_cache(namespace: str) -> None:
    """Delete cached state for a namespace."""
    cache_path = paths.state_cache_path(namespace)
    file.delete(cache_path)
