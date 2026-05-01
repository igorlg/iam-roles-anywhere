"""Shared CLI utilities.

Common options, AwsContext creation, error handling, output formatting.
"""

import json
import sys
from collections.abc import Callable
from dataclasses import asdict, is_dataclass
from enum import Enum
from typing import Any, ParamSpec, TypeVar

import click

from iam_ra_cli.lib.aws import AwsContext
from iam_ra_cli.lib.errors import (
    CAKeyNotFoundError,
    CAScopeAlreadyExistsError,
    CAScopeNotFoundError,
    HostAlreadyExistsError,
    HostNotFoundError,
    K8sClusterAlreadyExistsError,
    K8sClusterInUseError,
    K8sClusterNotFoundError,
    K8sUnsupportedCAModeError,
    K8sWorkloadAlreadyExistsError,
    K8sWorkloadNotFoundError,
    NotInitializedError,
    PCADescribeError,
    PCAGetCertError,
    PCAIssueCertError,
    PCANotActiveError,
    PCATimeoutError,
    RoleAlreadyExistsError,
    RoleInUseError,
    RoleNotFoundError,
    SecretsFileExistsError,
    SecretsManagerReadError,
    SOPSEncryptError,
    StackDeleteError,
    StackDeployError,
    StateLoadError,
    StateSaveError,
)
from iam_ra_cli.lib.result import Err, Ok, Result

# Default values
DEFAULT_NAMESPACE = "default"
DEFAULT_REGION = "ap-southeast-2"

# Type variables for decorators
P = ParamSpec("P")
T = TypeVar("T")


# Common CLI options as decorators
def namespace_option(fn: Callable[P, T]) -> Callable[P, T]:
    """Add --namespace/-n option."""
    return click.option(
        "--namespace",
        "-n",
        default=DEFAULT_NAMESPACE,
        show_default=True,
        help="Namespace identifier",
    )(fn)


def region_option(fn: Callable[P, T]) -> Callable[P, T]:
    """Add --region/-r option."""
    return click.option(
        "--region",
        "-r",
        default=DEFAULT_REGION,
        show_default=True,
        help="AWS region",
    )(fn)


def profile_option(fn: Callable[P, T]) -> Callable[P, T]:
    """Add --profile/-p option."""
    return click.option(
        "--profile",
        "-p",
        default=None,
        help="AWS profile",
    )(fn)


def json_option(fn: Callable[P, T]) -> Callable[P, T]:
    """Add --json flag for JSON output."""
    return click.option(
        "--json",
        "as_json",
        is_flag=True,
        help="Output as JSON",
    )(fn)


def aws_options(fn: Callable[P, T]) -> Callable[P, T]:
    """Add all AWS-related options (region, profile)."""
    fn = region_option(fn)
    fn = profile_option(fn)
    return fn


def common_options(fn: Callable[P, T]) -> Callable[P, T]:
    """Add all common options (namespace, region, profile)."""
    fn = namespace_option(fn)
    fn = aws_options(fn)
    return fn


def make_context(region: str, profile: str | None) -> AwsContext:
    """Create AwsContext from CLI options."""
    return AwsContext(region=region, profile=profile)


def handle_result(
    result: Result[T, Any],
    success_message: str | None = None,
    as_json: bool = False,
) -> T:
    """Handle a Result, exiting on error with appropriate message.

    On Ok: returns the value, optionally prints success message (suppressed
    when as_json=True so JSON consumers aren't polluted by human output).
    On Err: prints error and exits with code 1. When as_json=True, the error
    is emitted as structured JSON to stderr; otherwise it's human-readable
    red text.
    """
    match result:
        case Ok(value):
            if success_message and not as_json:
                click.secho(success_message, fg="green", bold=True, err=True)
            return value
        case Err(error):
            handle_error(error, as_json=as_json)
            sys.exit(1)  # Should never reach here, but for type checker


def handle_error(error: Any, as_json: bool = False) -> None:
    """Print error message and exit.

    When as_json=True, emit a structured error payload to stderr so that
    scripts can parse it with jq. Otherwise, print the human-readable
    red 'Error: ...' message (status quo behaviour).
    """
    if as_json:
        click.echo(render_json_error(error), err=True)
    else:
        message = _format_error(error)
        click.secho(f"Error: {message}", fg="red", err=True)
    sys.exit(1)


def _format_error(error: Any) -> str:
    """Format error for display."""
    match error:
        case NotInitializedError(namespace):
            return f"Namespace '{namespace}' is not initialized. Run 'iam-ra init' first."

        case RoleNotFoundError(namespace, role_name):
            return f"Role '{role_name}' not found in namespace '{namespace}'."

        case RoleAlreadyExistsError(namespace, role_name):
            return f"Role '{role_name}' already exists in namespace '{namespace}'."

        case RoleInUseError(role_name, hosts):
            hosts_str = ", ".join(hosts)
            return (
                f"Role '{role_name}' is in use by hosts: {hosts_str}. Use --force to delete anyway."
            )

        case HostNotFoundError(namespace, hostname):
            return f"Host '{hostname}' not found in namespace '{namespace}'."

        case HostAlreadyExistsError(namespace, hostname):
            return f"Host '{hostname}' already exists in namespace '{namespace}'. Use --overwrite to replace."

        case K8sClusterNotFoundError(cluster_name):
            return f"K8s cluster '{cluster_name}' not found. Run 'iam-ra k8s setup {cluster_name}' first."

        case K8sClusterAlreadyExistsError(cluster_name):
            return f"K8s cluster '{cluster_name}' already exists."

        case K8sClusterInUseError(cluster_name, workloads):
            workloads_str = ", ".join(workloads)
            return f"K8s cluster '{cluster_name}' is in use by workloads: {workloads_str}. Offboard them first."

        case K8sWorkloadNotFoundError(workload_name):
            return f"K8s workload '{workload_name}' not found."

        case K8sWorkloadAlreadyExistsError(workload_name):
            return f"K8s workload '{workload_name}' already exists."

        case K8sUnsupportedCAModeError(ca_mode):
            return f"CA mode '{ca_mode}' is not supported for K8s. Only 'self-signed' is supported."

        case CAKeyNotFoundError(expected_path):
            return f"CA private key not found at '{expected_path}'. Was 'iam-ra init' run on this machine?"

        case CAScopeNotFoundError(namespace, scope):
            return f"CA scope '{scope}' not found in namespace '{namespace}'. Run 'iam-ra ca setup --scope {scope}' first."

        case CAScopeAlreadyExistsError(namespace, scope):
            return f"CA scope '{scope}' already exists in namespace '{namespace}'."

        case StackDeployError(stack_name, status, reason):
            return f"Failed to deploy stack '{stack_name}': {status} - {reason}"

        case StackDeleteError(stack_name, status, reason):
            return f"Failed to delete stack '{stack_name}': {status} - {reason}"

        case StateLoadError(namespace, reason):
            return f"Failed to load state for '{namespace}': {reason}"

        case StateSaveError(namespace, reason):
            return f"Failed to save state for '{namespace}': {reason}"

        case SecretsManagerReadError(secret_arn, reason):
            return f"Failed to read secret '{secret_arn}': {reason}"

        case SOPSEncryptError(path, reason):
            return f"SOPS encryption failed for '{path}': {reason}"

        case SecretsFileExistsError(path):
            return f"Secrets file already exists: {path}"

        case PCADescribeError(pca_arn, reason):
            return f"Failed to describe ACM Private CA '{pca_arn}': {reason}"

        case PCANotActiveError(pca_arn, status):
            return (
                f"ACM Private CA '{pca_arn}' is in status '{status}', but must be "
                f"ACTIVE to issue certificates. Activate it in the AWS console or via "
                f"'aws acm-pca update-certificate-authority --status ACTIVE --certificate-authority-arn {pca_arn}'."
            )

        case PCAIssueCertError(pca_arn, reason):
            return f"Failed to issue certificate from ACM Private CA '{pca_arn}': {reason}"

        case PCAGetCertError(pca_arn, certificate_arn, reason):
            return (
                f"Failed to retrieve issued certificate '{certificate_arn}' from "
                f"ACM Private CA '{pca_arn}': {reason}"
            )

        case PCATimeoutError(pca_arn, certificate_arn):
            return (
                f"Timed out waiting for ACM Private CA '{pca_arn}' to issue certificate "
                f"'{certificate_arn}'. The request may still be in progress - check the AWS console."
            )

        case _:
            return str(error)


def to_json(obj: Any) -> str:
    """Convert object to JSON string.

    NOTE: this is the legacy helper. New code should use `render_json(payload)`
    which wraps the payload with a stable `schema_version` envelope. Kept for
    backwards-compat during the migration.
    """
    return json.dumps(_to_serializable(obj), indent=2)


# =============================================================================
# JSON output schema
#
# All --json output follows a shared, minimally-invasive envelope:
#
#   Success (stdout):
#     {
#       "schema_version": "v1",
#       ...command-specific fields...
#     }
#
#   Error (stderr, exit code non-zero):
#     {
#       "schema_version": "v1",
#       "error": {
#         "type": "<DataclassName>",
#         "message": "<human-readable>",
#         "fields": { ...dataclass attrs... }
#       }
#     }
#
# Versioning policy: additive changes to payload shape are safe under v1.
# Removing or renaming a field, or changing field semantics, requires bumping
# the schema_version (v2 etc.) and documenting the migration.
# =============================================================================

JSON_SCHEMA_VERSION = "v1"


def render_json(payload: dict[str, Any]) -> str:
    """Render a command's success payload with the versioned envelope.

    Args:
        payload: Command-specific fields. Will be merged with the schema
            version header so the resulting JSON object has
            `schema_version` at the top alongside the payload's own keys.

    Returns:
        Pretty-printed JSON string. Suitable for click.echo() to stdout.
    """
    envelope: dict[str, Any] = {"schema_version": JSON_SCHEMA_VERSION}
    envelope.update(_to_serializable(payload))
    return json.dumps(envelope, indent=2)


def render_json_error(error: Any) -> str:
    """Render an error as a structured JSON payload.

    Used when --json is set and a command fails. The resulting JSON has:
      - schema_version (stable envelope)
      - error.type (dataclass class name, for programmatic dispatch)
      - error.message (human-readable, matches _format_error output)
      - error.fields (dataclass attributes, so scripts can extract specifics)
    """
    from dataclasses import asdict, is_dataclass

    if is_dataclass(error) and not isinstance(error, type):
        fields = _to_serializable(asdict(error))
    else:
        fields = {}

    payload: dict[str, Any] = {
        "schema_version": JSON_SCHEMA_VERSION,
        "error": {
            "type": type(error).__name__,
            "message": _format_error(error),
            "fields": fields,
        },
    }
    return json.dumps(payload, indent=2)


def _to_serializable(obj: Any) -> Any:
    """Convert object to JSON-serializable form."""
    if obj is None:
        return None
    if isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, dict):
        return {k: _to_serializable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_serializable(v) for v in obj]
    if is_dataclass(obj) and not isinstance(obj, type):
        return _to_serializable(asdict(obj))
    return str(obj)


def echo_key_value(key: str, value: Any, indent: int = 0, err: bool = False) -> None:
    """Print a key-value pair with optional indentation."""
    prefix = "  " * indent
    click.echo(f"{prefix}{key}: {value}", err=err)


def echo_section(title: str) -> None:
    """Print a section header."""
    click.echo()
    click.secho(title, bold=True)
    click.echo("-" * len(title))
