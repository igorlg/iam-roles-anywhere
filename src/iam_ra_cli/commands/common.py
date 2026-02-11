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
    HostAlreadyExistsError,
    HostNotFoundError,
    K8sClusterAlreadyExistsError,
    K8sClusterInUseError,
    K8sClusterNotFoundError,
    K8sUnsupportedCAModeError,
    K8sWorkloadAlreadyExistsError,
    K8sWorkloadNotFoundError,
    NotInitializedError,
    RoleAlreadyExistsError,
    RoleInUseError,
    RoleNotFoundError,
    SecretsError,
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


def handle_result(result: Result[T, Any], success_message: str | None = None) -> T:
    """Handle a Result, exiting on error with appropriate message.

    On Ok: returns the value, optionally prints success message
    On Err: prints error and exits with code 1
    """
    match result:
        case Ok(value):
            if success_message:
                click.secho(success_message, fg="green", bold=True)
            return value
        case Err(error):
            handle_error(error)
            sys.exit(1)  # Should never reach here, but for type checker


def handle_error(error: Any) -> None:
    """Print error message and exit."""
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

        case StackDeployError(stack_name, status, reason):
            return f"Failed to deploy stack '{stack_name}': {status} - {reason}"

        case StackDeleteError(stack_name, status, reason):
            return f"Failed to delete stack '{stack_name}': {status} - {reason}"

        case StateLoadError(reason):
            return f"Failed to load state: {reason}"

        case StateSaveError(reason):
            return f"Failed to save state: {reason}"

        case SecretsError(reason):
            return f"Secrets error: {reason}"

        case _:
            return str(error)


def to_json(obj: Any) -> str:
    """Convert object to JSON string."""
    return json.dumps(_to_serializable(obj), indent=2)


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


def echo_key_value(key: str, value: Any, indent: int = 0) -> None:
    """Print a key-value pair with optional indentation."""
    prefix = "  " * indent
    click.echo(f"{prefix}{key}: {value}")


def echo_section(title: str) -> None:
    """Print a section header."""
    click.echo()
    click.secho(title, bold=True)
    click.echo("-" * len(title))
