"""Tests for K8s manifest generation and workflows."""

import tempfile
from pathlib import Path

import pytest
from moto import mock_aws

from iam_ra_cli.lib import state as state_module
from iam_ra_cli.lib.aws import AwsContext
from iam_ra_cli.lib.k8s import (
    DEFAULT_CA_SECRET_NAME,
    DEFAULT_CERT_DURATION_HOURS,
    DEFAULT_ISSUER_NAME,
    generate_ca_secret,
    generate_certificate,
    generate_cluster_manifests,
    generate_configmap,
    generate_issuer,
    generate_sample_pod,
    generate_workload_manifests,
)
from iam_ra_cli.lib.result import Err, Ok
from iam_ra_cli.models import (
    CA,
    Arn,
    CAMode,
    Init,
    Role,
    State,
)
from iam_ra_cli.workflows.k8s import (
    list_k8s,
    offboard,
    onboard,
    setup,
    teardown,
)

# =============================================================================
# Fixtures
# =============================================================================


SAMPLE_CA_CERT = """-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHBfpEgcMFvMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl
c3RjYTAeFw0yNDAyMTEwMDAwMDBaFw0yNTAyMTEwMDAwMDBaMBExDzANBgNVBAMM
BnRlc3RjYTBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC7o96HtiXYxvnKKjDLvQG+
5X3FUbEcdZuLM5hPMHUCQQCvOj8xBZNkxJ2HbJJxvO6BVnUUBG/btLTh8bLwL1d7
A0ITHLRsZNlINfECAwEAAaNTMFEwHQYDVR0OBBYEFJDVlR0CzoSIQx6hM5HABKpv
JH8fMB8GA1UdIwQYMBaAFJDVlR0CzoSIQx6hM5HABKpvJH8fMA8GA1UdEwEB/wQF
MAMBAf8wDQYJKoZIhvcNAQELBQADQQBxaVBm6CdpH5nH7n3t+nLwPfD0BxA=
-----END CERTIFICATE-----"""

SAMPLE_CA_KEY = """-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIJqdbllFipqJsrzu5ua19pGq7l2/YRP3GRI+ksp3xR3RoAoGCCqGSM49
AwEHoUQDQgAEZ430G7tL4/GTs3JKsmcxvvZkXoq1rZ40VP9zgeOSYOlVQZnNZLdl
IPq3pPTbbMOQ2NwlKgrosN9MzKZM5BPOUw==
-----END EC PRIVATE KEY-----"""


@pytest.fixture
def aws_context(monkeypatch):
    """Create an AwsContext for testing with isolated XDG data dir."""
    with tempfile.TemporaryDirectory() as tmpdir:
        data_dir = Path(tmpdir) / "data"
        data_dir.mkdir()
        monkeypatch.setenv("XDG_DATA_HOME", str(data_dir))

        # Create CA private key in the expected location
        ca_key_dir = data_dir / "iam-ra" / "default"
        ca_key_dir.mkdir(parents=True)
        (ca_key_dir / "ca-private-key.pem").write_text(SAMPLE_CA_KEY)

        with mock_aws():
            ctx = AwsContext(region="us-east-1")
            yield ctx


@pytest.fixture
def initialized_state(aws_context: AwsContext) -> State:
    """Create an initialized state with CA and roles."""
    # Invalidate any cached state first
    state_module.invalidate_cache("default")

    # Create S3 bucket
    aws_context.s3.create_bucket(Bucket="test-bucket")

    # Upload CA cert
    aws_context.s3.put_object(
        Bucket="test-bucket",
        Key="default/ca/certificate.pem",
        Body=SAMPLE_CA_CERT.encode(),
    )

    # Create SSM parameter
    aws_context.ssm.put_parameter(
        Name="/iam-ra/default/state-location",
        Value="s3://test-bucket/default/state.json",
        Type="String",
    )

    # Create state with NO k8s resources (clean state)
    state = State(
        namespace="default",
        region="us-east-1",
        version="1.0.0",
        init=Init(
            stack_name="iam-ra-default-init",
            bucket_arn=Arn("arn:aws:s3:::test-bucket"),
            kms_key_arn=Arn("arn:aws:kms:us-east-1:123456789012:key/test-key"),
        ),
        ca=CA(
            stack_name="iam-ra-default-ca",
            mode=CAMode.SELF_SIGNED,
            trust_anchor_arn=Arn(
                "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/ta-123"
            ),
        ),
        roles={
            "admin": Role(
                stack_name="iam-ra-default-role-admin",
                role_arn=Arn("arn:aws:iam::123456789012:role/admin"),
                profile_arn=Arn(
                    "arn:aws:rolesanywhere:us-east-1:123456789012:profile/admin-profile"
                ),
            ),
            "readonly": Role(
                stack_name="iam-ra-default-role-readonly",
                role_arn=Arn("arn:aws:iam::123456789012:role/readonly"),
                profile_arn=Arn(
                    "arn:aws:rolesanywhere:us-east-1:123456789012:profile/readonly-profile"
                ),
            ),
        },
        k8s_clusters={},
        k8s_workloads={},
    )

    # Save state
    aws_context.s3.put_object(
        Bucket="test-bucket",
        Key="default/state.json",
        Body=state.to_json().encode(),
    )

    return state


# =============================================================================
# Manifest Generation Tests
# =============================================================================


class TestGenerateCaSecret:
    """Tests for generate_ca_secret."""

    def test_generates_valid_yaml(self):
        """Should generate valid K8s Secret YAML."""
        result = generate_ca_secret(SAMPLE_CA_CERT, SAMPLE_CA_KEY)

        assert "apiVersion: v1" in result
        assert "kind: Secret" in result
        assert "type: kubernetes.io/tls" in result
        assert "tls.crt:" in result
        assert "tls.key:" in result

    def test_uses_default_name(self):
        """Should use default name if not specified."""
        result = generate_ca_secret(SAMPLE_CA_CERT, SAMPLE_CA_KEY)
        assert f"name: {DEFAULT_CA_SECRET_NAME}" in result

    def test_uses_custom_name(self):
        """Should use custom name if specified."""
        result = generate_ca_secret(SAMPLE_CA_CERT, SAMPLE_CA_KEY, name="my-ca")
        assert "name: my-ca" in result

    def test_uses_custom_namespace(self):
        """Should use custom namespace if specified."""
        result = generate_ca_secret(SAMPLE_CA_CERT, SAMPLE_CA_KEY, namespace="prod")
        assert "namespace: prod" in result

    def test_includes_certificate(self):
        """Should include the CA certificate."""
        result = generate_ca_secret(SAMPLE_CA_CERT, SAMPLE_CA_KEY)
        assert "BEGIN CERTIFICATE" in result
        assert "END CERTIFICATE" in result

    def test_includes_private_key(self):
        """Should include the CA private key."""
        result = generate_ca_secret(SAMPLE_CA_CERT, SAMPLE_CA_KEY)
        assert "BEGIN EC PRIVATE KEY" in result
        assert "END EC PRIVATE KEY" in result


class TestGenerateIssuer:
    """Tests for generate_issuer."""

    def test_generates_valid_yaml(self):
        """Should generate valid cert-manager Issuer YAML."""
        result = generate_issuer()

        assert "apiVersion: cert-manager.io/v1" in result
        assert "kind: Issuer" in result

    def test_uses_default_name(self):
        """Should use default name if not specified."""
        result = generate_issuer()
        assert f"name: {DEFAULT_ISSUER_NAME}" in result

    def test_references_ca_secret(self):
        """Should reference the CA secret."""
        result = generate_issuer(ca_secret_name="my-ca")
        assert "secretName: my-ca" in result


class TestGenerateCertificate:
    """Tests for generate_certificate."""

    def test_generates_valid_yaml(self):
        """Should generate valid cert-manager Certificate YAML."""
        result = generate_certificate("my-app")

        assert "apiVersion: cert-manager.io/v1" in result
        assert "kind: Certificate" in result

    def test_uses_workload_name_in_naming(self):
        """Should use workload name for cert and secret names."""
        result = generate_certificate("payment-service")
        assert "name: payment-service-cert" in result
        assert "secretName: payment-service-cert" in result

    def test_sets_common_name(self):
        """Should set CN to workload name by default."""
        result = generate_certificate("my-app")
        assert 'commonName: "my-app"' in result

    def test_uses_custom_duration(self):
        """Should use custom duration if specified."""
        result = generate_certificate("my-app", duration_hours=12)
        assert "duration: 12h0m0s" in result

    def test_uses_default_duration(self):
        """Should use default duration."""
        result = generate_certificate("my-app")
        assert f"duration: {DEFAULT_CERT_DURATION_HOURS}h0m0s" in result

    def test_references_issuer(self):
        """Should reference the specified issuer."""
        result = generate_certificate("my-app", issuer_name="custom-issuer")
        assert "name: custom-issuer" in result


class TestGenerateConfigMap:
    """Tests for generate_configmap."""

    def test_generates_valid_yaml(self):
        """Should generate valid K8s ConfigMap YAML."""
        result = generate_configmap(
            "my-app",
            "arn:aws:rolesanywhere:us-east-1:123:trust-anchor/ta",
            "arn:aws:rolesanywhere:us-east-1:123:profile/p",
            "arn:aws:iam::123:role/r",
        )

        assert "apiVersion: v1" in result
        assert "kind: ConfigMap" in result

    def test_includes_all_arns(self):
        """Should include all ARNs."""
        result = generate_configmap(
            "my-app",
            "trust-anchor-arn",
            "profile-arn",
            "role-arn",
        )

        assert "TRUST_ANCHOR_ARN" in result
        assert "PROFILE_ARN" in result
        assert "ROLE_ARN" in result

    def test_uses_workload_name(self):
        """Should use workload name in configmap name."""
        result = generate_configmap("payment-service", "ta", "p", "r")
        assert "name: payment-service-iam-ra-config" in result


class TestGenerateSamplePod:
    """Tests for generate_sample_pod."""

    def test_generates_valid_yaml(self):
        """Should generate valid K8s Pod YAML."""
        result = generate_sample_pod("my-app")

        assert "apiVersion: v1" in result
        assert "kind: Pod" in result

    def test_includes_app_container(self):
        """Should include application container."""
        result = generate_sample_pod("my-app")
        assert "name: app" in result

    def test_includes_sidecar(self):
        """Should include IAM-RA sidecar."""
        result = generate_sample_pod("my-app")
        assert "name: iam-ra-sidecar" in result

    def test_sets_metadata_endpoint(self):
        """Should configure IMDS endpoint env var."""
        result = generate_sample_pod("my-app")
        assert "AWS_EC2_METADATA_SERVICE_ENDPOINT" in result
        assert "http://127.0.0.1:9911/" in result

    def test_mounts_cert_volume(self):
        """Should mount certificate volume."""
        result = generate_sample_pod("my-app")
        assert "iam-ra-cert" in result
        assert "/var/run/secrets/iam-ra" in result


class TestGenerateClusterManifests:
    """Tests for generate_cluster_manifests."""

    def test_returns_cluster_manifests(self):
        """Should return ClusterManifests object."""
        result = generate_cluster_manifests(SAMPLE_CA_CERT, SAMPLE_CA_KEY)

        assert result.ca_secret is not None
        assert result.issuer is not None

    def test_to_yaml_combines_manifests(self):
        """Should combine manifests with separator."""
        result = generate_cluster_manifests(SAMPLE_CA_CERT, SAMPLE_CA_KEY)
        yaml = result.to_yaml()

        assert "---" in yaml
        assert "kind: Secret" in yaml
        assert "kind: Issuer" in yaml


class TestGenerateWorkloadManifests:
    """Tests for generate_workload_manifests."""

    def test_returns_workload_manifests(self):
        """Should return WorkloadManifests object."""
        result = generate_workload_manifests(
            "my-app",
            "ta-arn",
            "profile-arn",
            "role-arn",
        )

        assert result.certificate is not None
        assert result.configmap is not None
        assert result.pod is not None

    def test_to_yaml_combines_manifests(self):
        """Should combine manifests with separator."""
        result = generate_workload_manifests(
            "my-app",
            "ta-arn",
            "profile-arn",
            "role-arn",
        )
        yaml = result.to_yaml()

        assert yaml.count("---") == 2
        assert "kind: Certificate" in yaml
        assert "kind: ConfigMap" in yaml
        assert "kind: Pod" in yaml


# =============================================================================
# Workflow Tests
# =============================================================================


class TestSetup:
    """Tests for k8s setup workflow."""

    def test_setup_creates_cluster(self, aws_context, initialized_state):
        """Should create cluster and return manifests."""
        result = setup(aws_context, "default", "prod-cluster")

        assert isinstance(result, Ok)
        assert result.value.cluster.name == "prod-cluster"
        assert result.value.manifests.ca_secret is not None
        assert result.value.manifests.issuer is not None

    def test_setup_fails_if_not_initialized(self, aws_context):
        """Should fail if namespace not initialized."""
        result = setup(aws_context, "nonexistent", "prod")

        assert isinstance(result, Err)

    def test_setup_is_idempotent(self, aws_context, initialized_state):
        """Should succeed if cluster already exists (idempotent)."""
        # First setup
        result1 = setup(aws_context, "default", "prod")
        assert isinstance(result1, Ok)

        # Second setup should also succeed
        result2 = setup(aws_context, "default", "prod")
        assert isinstance(result2, Ok)
        assert result2.value.cluster.name == "prod"
        assert result2.value.manifests.ca_secret is not None

        # Should still be only one cluster in state
        list_result = list_k8s(aws_context, "default")
        assert isinstance(list_result, Ok)
        assert len(list_result.value.clusters) == 1

    def test_setup_saves_cluster_to_state(self, aws_context, initialized_state):
        """Should save cluster to state."""
        setup(aws_context, "default", "prod")

        result = list_k8s(aws_context, "default")
        assert isinstance(result, Ok)
        assert "prod" in result.value.clusters


class TestTeardown:
    """Tests for k8s teardown workflow."""

    def test_teardown_removes_cluster(self, aws_context, initialized_state):
        """Should remove cluster from state."""
        setup(aws_context, "default", "prod")
        result = teardown(aws_context, "default", "prod")

        assert isinstance(result, Ok)

        list_result = list_k8s(aws_context, "default")
        assert "prod" not in list_result.value.clusters

    def test_teardown_fails_if_cluster_not_found(self, aws_context, initialized_state):
        """Should fail if cluster doesn't exist."""
        result = teardown(aws_context, "default", "nonexistent")
        assert isinstance(result, Err)

    def test_teardown_fails_if_cluster_in_use(self, aws_context, initialized_state):
        """Should fail if cluster has workloads."""
        setup(aws_context, "default", "prod")
        onboard(aws_context, "default", "my-app", "prod", "admin")

        result = teardown(aws_context, "default", "prod")
        assert isinstance(result, Err)


class TestOnboard:
    """Tests for k8s onboard workflow."""

    def test_onboard_creates_workload(self, aws_context, initialized_state):
        """Should create workload and return manifests."""
        setup(aws_context, "default", "prod")
        result = onboard(aws_context, "default", "my-app", "prod", "admin")

        assert isinstance(result, Ok)
        assert result.value.workload.name == "my-app"
        assert result.value.workload.cluster_name == "prod"
        assert result.value.workload.role_name == "admin"

    def test_onboard_fails_if_cluster_not_found(self, aws_context, initialized_state):
        """Should fail if cluster doesn't exist."""
        result = onboard(aws_context, "default", "my-app", "nonexistent", "admin")
        assert isinstance(result, Err)

    def test_onboard_fails_if_role_not_found(self, aws_context, initialized_state):
        """Should fail if role doesn't exist."""
        setup(aws_context, "default", "prod")
        result = onboard(aws_context, "default", "my-app", "prod", "nonexistent")
        assert isinstance(result, Err)

    def test_onboard_is_idempotent(self, aws_context, initialized_state):
        """Should succeed if workload already exists (idempotent)."""
        setup(aws_context, "default", "prod")
        result1 = onboard(aws_context, "default", "my-app", "prod", "admin")
        assert isinstance(result1, Ok)

        result2 = onboard(aws_context, "default", "my-app", "prod", "admin")
        assert isinstance(result2, Ok)
        assert result2.value.workload.name == "my-app"
        assert result2.value.manifests.configmap is not None

        # Should still be only one workload in state
        list_result = list_k8s(aws_context, "default")
        assert isinstance(list_result, Ok)
        assert len(list_result.value.workloads) == 1

    def test_onboard_manifests_include_correct_arns(self, aws_context, initialized_state):
        """Should include correct ARNs in manifests."""
        setup(aws_context, "default", "prod")
        result = onboard(aws_context, "default", "my-app", "prod", "admin")

        assert isinstance(result, Ok)
        configmap = result.value.manifests.configmap
        assert "trust-anchor/ta-123" in configmap
        assert "profile/admin-profile" in configmap
        assert "role/admin" in configmap


class TestOffboard:
    """Tests for k8s offboard workflow."""

    def test_offboard_removes_workload(self, aws_context, initialized_state):
        """Should remove workload from state."""
        setup(aws_context, "default", "prod")
        onboard(aws_context, "default", "my-app", "prod", "admin")

        result = offboard(aws_context, "default", "my-app")
        assert isinstance(result, Ok)

        list_result = list_k8s(aws_context, "default")
        assert "my-app" not in list_result.value.workloads

    def test_offboard_fails_if_workload_not_found(self, aws_context, initialized_state):
        """Should fail if workload doesn't exist."""
        result = offboard(aws_context, "default", "nonexistent")
        assert isinstance(result, Err)


class TestListK8s:
    """Tests for k8s list workflow."""

    def test_list_empty(self, aws_context, initialized_state):
        """Should return empty lists when no k8s resources."""
        result = list_k8s(aws_context, "default")

        assert isinstance(result, Ok)
        assert result.value.clusters == {}
        assert result.value.workloads == {}

    def test_list_returns_all(self, aws_context, initialized_state):
        """Should return all clusters and workloads."""
        setup(aws_context, "default", "prod")
        setup(aws_context, "default", "staging")
        onboard(aws_context, "default", "app1", "prod", "admin")
        onboard(aws_context, "default", "app2", "staging", "readonly")

        result = list_k8s(aws_context, "default")

        assert isinstance(result, Ok)
        assert len(result.value.clusters) == 2
        assert len(result.value.workloads) == 2

    def test_list_filters_by_cluster(self, aws_context, initialized_state):
        """Should filter by cluster name."""
        setup(aws_context, "default", "prod")
        setup(aws_context, "default", "staging")
        onboard(aws_context, "default", "app1", "prod", "admin")
        onboard(aws_context, "default", "app2", "staging", "readonly")

        result = list_k8s(aws_context, "default", cluster_name="prod")

        assert isinstance(result, Ok)
        assert len(result.value.clusters) == 1
        assert "prod" in result.value.clusters
        assert len(result.value.workloads) == 1
        assert "app1" in result.value.workloads
