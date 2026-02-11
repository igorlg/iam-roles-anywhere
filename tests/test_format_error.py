"""Tests for commands/common.py - _format_error pattern matching.

Every error type gets its own test to catch:
- Type aliases used in match/case (crash at runtime)
- Wrong positional destructuring (silent wrong values)
- Missing case arms (falls through to generic str())
"""

from pathlib import Path

from iam_ra_cli.commands.common import _format_error
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
    SecretsFileExistsError,
    SecretsManagerReadError,
    SOPSEncryptError,
    StackDeleteError,
    StackDeployError,
    StateLoadError,
    StateSaveError,
)


class TestFormatInfraErrors:
    """Tests for infrastructure error formatting."""

    def test_not_initialized(self) -> None:
        error = NotInitializedError(namespace="prod")
        result = _format_error(error)
        assert "prod" in result
        assert "not initialized" in result
        assert "iam-ra init" in result

    def test_stack_deploy_error(self) -> None:
        error = StackDeployError(
            stack_name="my-stack",
            status="ROLLBACK_COMPLETE",
            reason="Resource limit exceeded",
        )
        result = _format_error(error)
        assert "my-stack" in result
        assert "ROLLBACK_COMPLETE" in result
        assert "Resource limit exceeded" in result

    def test_stack_delete_error(self) -> None:
        error = StackDeleteError(
            stack_name="my-stack",
            status="DELETE_FAILED",
            reason="Cannot delete non-empty bucket",
        )
        result = _format_error(error)
        assert "my-stack" in result
        assert "DELETE_FAILED" in result
        assert "Cannot delete non-empty bucket" in result


class TestFormatRoleErrors:
    """Tests for role error formatting."""

    def test_role_not_found(self) -> None:
        error = RoleNotFoundError(namespace="default", role_name="readonly")
        result = _format_error(error)
        assert "readonly" in result
        assert "default" in result
        assert "not found" in result

    def test_role_already_exists(self) -> None:
        error = RoleAlreadyExistsError(namespace="default", role_name="admin")
        result = _format_error(error)
        assert "admin" in result
        assert "default" in result
        assert "already exists" in result

    def test_role_in_use(self) -> None:
        error = RoleInUseError(role_name="readonly", hosts=("host-a", "host-b"))
        result = _format_error(error)
        assert "readonly" in result
        assert "host-a" in result
        assert "host-b" in result
        assert "--force" in result


class TestFormatHostErrors:
    """Tests for host error formatting."""

    def test_host_not_found(self) -> None:
        error = HostNotFoundError(namespace="default", hostname="lnv-01")
        result = _format_error(error)
        assert "lnv-01" in result
        assert "default" in result
        assert "not found" in result

    def test_host_already_exists(self) -> None:
        error = HostAlreadyExistsError(namespace="staging", hostname="lnv-01")
        result = _format_error(error)
        assert "lnv-01" in result
        assert "staging" in result
        assert "already exists" in result
        assert "--overwrite" in result


class TestFormatK8sErrors:
    """Tests for K8s error formatting."""

    def test_cluster_not_found(self) -> None:
        error = K8sClusterNotFoundError(cluster_name="prod-cluster")
        result = _format_error(error)
        assert "prod-cluster" in result
        assert "not found" in result

    def test_cluster_already_exists(self) -> None:
        error = K8sClusterAlreadyExistsError(cluster_name="dev-cluster")
        result = _format_error(error)
        assert "dev-cluster" in result
        assert "already exists" in result

    def test_cluster_in_use(self) -> None:
        error = K8sClusterInUseError(
            cluster_name="prod-cluster",
            workloads=("api-server", "worker"),
        )
        result = _format_error(error)
        assert "prod-cluster" in result
        assert "api-server" in result
        assert "worker" in result

    def test_workload_not_found(self) -> None:
        error = K8sWorkloadNotFoundError(workload_name="api-server")
        result = _format_error(error)
        assert "api-server" in result
        assert "not found" in result

    def test_workload_already_exists(self) -> None:
        error = K8sWorkloadAlreadyExistsError(workload_name="api-server")
        result = _format_error(error)
        assert "api-server" in result
        assert "already exists" in result

    def test_unsupported_ca_mode(self) -> None:
        error = K8sUnsupportedCAModeError(ca_mode="acm-pca")
        result = _format_error(error)
        assert "acm-pca" in result
        assert "not supported" in result


class TestFormatStateErrors:
    """Tests for state error formatting."""

    def test_state_load_error_includes_namespace_and_reason(self) -> None:
        error = StateLoadError(namespace="prod", reason="JSON decode failed")
        result = _format_error(error)
        assert "prod" in result
        assert "JSON decode failed" in result

    def test_state_save_error_includes_namespace_and_reason(self) -> None:
        error = StateSaveError(namespace="staging", reason="S3 access denied")
        result = _format_error(error)
        assert "staging" in result
        assert "S3 access denied" in result

    def test_state_load_error_does_not_swap_fields(self) -> None:
        """Regression: positional destructuring must match field order."""
        error = StateLoadError(namespace="my-ns", reason="my-reason")
        result = _format_error(error)
        # The namespace should appear in the namespace slot, not the reason slot
        assert "my-ns" in result
        assert "my-reason" in result
        # Verify they're not swapped by checking the message structure
        ns_pos = result.index("my-ns")
        reason_pos = result.index("my-reason")
        assert ns_pos < reason_pos, "namespace should appear before reason in the message"

    def test_state_save_error_does_not_swap_fields(self) -> None:
        """Regression: positional destructuring must match field order."""
        error = StateSaveError(namespace="my-ns", reason="my-reason")
        result = _format_error(error)
        ns_pos = result.index("my-ns")
        reason_pos = result.index("my-reason")
        assert ns_pos < reason_pos, "namespace should appear before reason in the message"


class TestFormatSecretsErrors:
    """Tests for secrets error formatting.

    Regression: SecretsError is a type alias (union), not a class.
    Each concrete type must have its own case arm.
    """

    def test_secrets_manager_read_error(self) -> None:
        error = SecretsManagerReadError(
            secret_arn="arn:aws:secretsmanager:us-east-1:123456789012:secret:my-secret",
            reason="Access denied",
        )
        result = _format_error(error)
        assert "my-secret" in result
        assert "Access denied" in result

    def test_sops_encrypt_error(self) -> None:
        error = SOPSEncryptError(
            path=Path("/home/user/.secrets/host.yaml"),
            reason="KMS key not found",
        )
        result = _format_error(error)
        assert "host.yaml" in result
        assert "KMS key not found" in result

    def test_secrets_file_exists_error(self) -> None:
        error = SecretsFileExistsError(path=Path("/home/user/.secrets/host.yaml"))
        result = _format_error(error)
        assert "host.yaml" in result
        assert "already exists" in result


class TestFormatUnknownError:
    """Tests for the fallback case."""

    def test_unknown_error_uses_str(self) -> None:
        result = _format_error("something unexpected")
        assert result == "something unexpected"

    def test_unknown_error_with_custom_object(self) -> None:
        class WeirdError:
            def __str__(self) -> str:
                return "weird thing happened"

        result = _format_error(WeirdError())
        assert result == "weird thing happened"
