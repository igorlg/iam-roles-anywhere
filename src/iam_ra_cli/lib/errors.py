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
class AccountMismatchError:
    """The active AWS credentials are for a different account than the one
    this namespace was initialised in.

    A namespace's SSM parameter, S3 bucket, and KMS key all live in one
    account. Running state-mutating commands with credentials for a
    different account either fails late (access denied) or silently
    crosses into the wrong account. This error fires at workflow entry
    time so the user can switch profiles before anything happens.
    """

    namespace: str
    expected_account_id: str
    actual_account_id: str


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


@dataclass(frozen=True, slots=True)
class CAScopeNotFoundError:
    """CA scope does not exist."""

    namespace: str
    scope: str


@dataclass(frozen=True, slots=True)
class CAScopeAlreadyExistsError:
    """CA scope already exists."""

    namespace: str
    scope: str


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


@dataclass(frozen=True, slots=True)
class RoleScopeMismatchError:
    """Attempted to attach a role to a host, but the role's scope differs
    from the host's scope.

    A host's cert is issued under one scope's CA / trust anchor and can
    only assume roles whose profiles are attached to that same trust anchor.
    Crossing scopes would require a second cert (scenario 3, multi-identity).
    """

    namespace: str
    hostname: str
    host_scope: str
    role_name: str
    role_scope: str


@dataclass(frozen=True, slots=True)
class CannotRemoveLastRoleError:
    """Refused to remove the last remaining role from a host.

    A host with zero roles has a cert but nothing to assume, which leaves
    it in an unusable state. `iam-ra host offboard <hostname>` is the right
    command to remove a host entirely.
    """

    namespace: str
    hostname: str
    role_name: str


# =============================================================================
# CSR / Certificate Signing Errors
# =============================================================================


@dataclass(frozen=True, slots=True)
class CsrParseError:
    """The supplied bytes are not a valid PEM certificate signing request."""

    reason: str


@dataclass(frozen=True, slots=True)
class CsrInvalidSignatureError:
    """The CSR's self-signature does not verify against its own public key.

    A CSR is self-signed by the requesting key, which proves the requester
    holds the private key for the public key being certified (proof of
    possession). A CSR that fails this check must never be signed - it may
    be a mangled transfer, or an attempt to get a certificate issued for
    someone else's public key.
    """


@dataclass(frozen=True, slots=True)
class CsrUnsupportedKeyError:
    """The CSR's public key is of a type or size this CA will not certify.

    IAM Roles Anywhere signs CreateSession requests with RSA or ECDSA (or
    ML-DSA), so Ed25519/Ed448/DSA keys are unusable even if the CA would
    happily sign them. Undersized RSA is rejected on strength grounds.
    """

    key_type: str
    reason: str


@dataclass(frozen=True, slots=True)
class CsrSubjectMismatchError:
    """A CSR asked to be certified under a different name than the host being
    approved.

    Only relevant on the ACM Private CA path. PCA copies the subject out of the
    CSR and the EndEntityClientAuthCertificate template does not allow an API
    override, so unlike the self-signed path we cannot simply rebuild the
    subject - the mismatch has to be a refusal.

    A benign cause is running `host request` for one hostname and
    `host approve` for another. The hostile case is a compromised host asking
    for a certificate that names a different host.
    """

    expected_common_name: str
    requested_common_name: str | None


# =============================================================================
# Key Store Errors
# =============================================================================


@dataclass(frozen=True, slots=True)
class KeyAlreadyExistsError:
    """A key already exists for this label and overwrite was not requested.

    Overwriting silently would strand the previously issued certificate,
    which stays valid against the trust anchor until it expires unless a CRL
    revoking it is imported - something this tool does not do. So replacing a
    key is deliberately opt-in.
    """

    backend: str
    label: str
    location: str


@dataclass(frozen=True, slots=True)
class KeyNotFoundError:
    """No key exists for this label in the given store."""

    backend: str
    label: str
    location: str


@dataclass(frozen=True, slots=True)
class KeyStoreOperationError:
    """A key store operation failed."""

    backend: str
    operation: str
    reason: str


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



# =============================================================================
# K8s Errors
# =============================================================================


@dataclass(frozen=True, slots=True)
class K8sClusterNotFoundError:
    """K8s cluster not found in state."""

    cluster_name: str


@dataclass(frozen=True, slots=True)
class K8sClusterAlreadyExistsError:
    """K8s cluster already exists in state."""

    cluster_name: str


@dataclass(frozen=True, slots=True)
class K8sClusterInUseError:
    """K8s cluster is in use by workloads."""

    cluster_name: str
    workloads: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class K8sWorkloadNotFoundError:
    """K8s workload not found in state."""

    workload_name: str


@dataclass(frozen=True, slots=True)
class K8sWorkloadAlreadyExistsError:
    """K8s workload already exists in state."""

    workload_name: str


@dataclass(frozen=True, slots=True)
class K8sUnsupportedCAModeError:
    """CA mode not supported for K8s integration."""

    ca_mode: str


# =============================================================================
# PCA Errors
# =============================================================================


@dataclass(frozen=True, slots=True)
class PCADescribeError:
    """Failed to describe ACM PCA."""

    pca_arn: str
    reason: str


@dataclass(frozen=True, slots=True)
class PCANotActiveError:
    """ACM PCA is not in ACTIVE status - cannot issue certificates.

    Possible statuses: CREATING, PENDING_CERTIFICATE, DISABLED, DELETED,
    EXPIRED, FAILED. A PCA must be ACTIVE before it can issue end-entity
    certificates.
    """

    pca_arn: str
    status: str


@dataclass(frozen=True, slots=True)
class PCAIssueCertError:
    """Failed to issue certificate via ACM PCA."""

    pca_arn: str
    reason: str


@dataclass(frozen=True, slots=True)
class PCAGetCertError:
    """Failed to retrieve issued certificate from ACM PCA."""

    pca_arn: str
    certificate_arn: str
    reason: str


@dataclass(frozen=True, slots=True)
class PCATimeoutError:
    """Timed out waiting for ACM PCA to issue certificate."""

    pca_arn: str
    certificate_arn: str


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
    | PCADescribeError
    | PCANotActiveError
    | PCAIssueCertError
    | PCAGetCertError
    | PCATimeoutError
)
type OffboardError = NotInitializedError | HostNotFoundError | StackDeleteError
type CsrError = (
    CsrParseError | CsrInvalidSignatureError | CsrUnsupportedKeyError | CsrSubjectMismatchError
)
type KeyStoreError = (
    KeyAlreadyExistsError | KeyNotFoundError | KeyStoreOperationError | CsrParseError
)
