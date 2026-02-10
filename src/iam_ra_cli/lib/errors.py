"""Error types for IAM Roles Anywhere CLI.

All errors are frozen dataclasses - no exceptions in business logic.
Pattern match on these in the CLI layer to provide user-friendly messages.
"""

from dataclasses import dataclass
from pathlib import Path

# =============================================================================
# Infrastructure Errors
# =============================================================================


@dataclass(frozen=True, slots=True)
class NotInitializedError:
    """Namespace has not been initialized."""

    namespace: str


@dataclass(frozen=True, slots=True)
class StackDeployError:
    """CloudFormation stack deployment failed."""

    stack_name: str
    status: str
    reason: str


@dataclass(frozen=True, slots=True)
class StackDeleteError:
    """CloudFormation stack deletion failed."""

    stack_name: str
    status: str
    reason: str


# =============================================================================
# CA Errors
# =============================================================================


@dataclass(frozen=True, slots=True)
class CAKeyNotFoundError:
    """CA private key not found locally (self-signed mode)."""

    expected_path: Path


@dataclass(frozen=True, slots=True)
class CACertNotFoundError:
    """CA certificate not found in S3."""

    bucket: str
    key: str


# =============================================================================
# Role Errors
# =============================================================================


@dataclass(frozen=True, slots=True)
class RoleNotFoundError:
    """Role does not exist."""

    namespace: str
    role_name: str


@dataclass(frozen=True, slots=True)
class RoleAlreadyExistsError:
    """Role already exists."""

    namespace: str
    role_name: str


@dataclass(frozen=True, slots=True)
class RoleInUseError:
    """Role is in use by one or more hosts."""

    role_name: str
    hosts: tuple[str, ...]


# =============================================================================
# Host Errors
# =============================================================================


@dataclass(frozen=True, slots=True)
class HostNotFoundError:
    """Host does not exist."""

    namespace: str
    hostname: str


@dataclass(frozen=True, slots=True)
class HostAlreadyExistsError:
    """Host already exists."""

    namespace: str
    hostname: str


# =============================================================================
# Storage Errors
# =============================================================================


@dataclass(frozen=True, slots=True)
class S3ReadError:
    """Failed to read from S3."""

    bucket: str
    key: str
    reason: str


@dataclass(frozen=True, slots=True)
class S3WriteError:
    """Failed to write to S3."""

    bucket: str
    key: str
    reason: str


@dataclass(frozen=True, slots=True)
class SSMReadError:
    """Failed to read from SSM Parameter Store."""

    parameter_name: str
    reason: str


@dataclass(frozen=True, slots=True)
class SSMWriteError:
    """Failed to write to SSM Parameter Store."""

    parameter_name: str
    reason: str


@dataclass(frozen=True, slots=True)
class SecretsManagerReadError:
    """Failed to read from Secrets Manager."""

    secret_arn: str
    reason: str


# =============================================================================
# Secrets File Errors
# =============================================================================


@dataclass(frozen=True, slots=True)
class SOPSEncryptError:
    """SOPS encryption failed."""

    path: Path
    reason: str


@dataclass(frozen=True, slots=True)
class SecretsFileExistsError:
    """Secrets file already exists."""

    path: Path


# =============================================================================
# State Errors
# =============================================================================


@dataclass(frozen=True, slots=True)
class StateLoadError:
    """Failed to load state."""

    namespace: str
    reason: str


@dataclass(frozen=True, slots=True)
class StateSaveError:
    """Failed to save state."""

    namespace: str
    reason: str


# =============================================================================
# Type Aliases for Error Unions
# =============================================================================

type InitError = StackDeployError
type CAError = StackDeployError | CAKeyNotFoundError | CACertNotFoundError | S3ReadError
type RoleError = NotInitializedError | RoleAlreadyExistsError | StackDeployError
type DeleteRoleError = NotInitializedError | RoleNotFoundError | RoleInUseError | StackDeleteError
type HostError = (
    NotInitializedError
    | RoleNotFoundError
    | HostAlreadyExistsError
    | CAKeyNotFoundError
    | CACertNotFoundError
    | S3ReadError
    | S3WriteError
    | StackDeployError
)
type OffboardError = NotInitializedError | HostNotFoundError | StackDeleteError
type SecretsError = SecretsManagerReadError | SOPSEncryptError | SecretsFileExistsError
