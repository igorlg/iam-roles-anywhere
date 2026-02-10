"""Tests for lib/state.py - State management with SSM and S3."""

import json
import tempfile
from pathlib import Path

import pytest
from moto import mock_aws

from iam_ra_cli.lib import state as state_module
from iam_ra_cli.lib.result import Err, Ok
from iam_ra_cli.models import CA, Arn, CAMode, Host, Init, Role, State


@pytest.fixture
def aws_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    """Mock AWS credentials for moto."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "ap-southeast-2")


@pytest.fixture
def temp_cache_dir(monkeypatch: pytest.MonkeyPatch):
    """Create temporary cache directory and patch paths module."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cache_dir = Path(tmpdir)

        # Patch the paths module to use temp directory
        def mock_state_cache_path(namespace: str) -> Path:
            return cache_dir / namespace / "state.json"

        monkeypatch.setattr("iam_ra_cli.lib.state.paths.state_cache_path", mock_state_cache_path)
        yield cache_dir


@pytest.fixture
def aws_clients(aws_credentials: None, temp_cache_dir: Path):
    """Create mocked SSM and S3 clients."""
    import boto3

    with mock_aws():
        ssm = boto3.client("ssm", region_name="ap-southeast-2")
        s3 = boto3.client("s3", region_name="ap-southeast-2")

        # Create test bucket
        s3.create_bucket(
            Bucket="test-bucket",
            CreateBucketConfiguration={"LocationConstraint": "ap-southeast-2"},
        )

        yield ssm, s3


@pytest.fixture
def sample_state() -> State:
    """Create a sample state for testing."""
    return State(
        namespace="test",
        region="ap-southeast-2",
        version="0.1.0",
        init=Init(
            stack_name="iam-ra-test-init",
            bucket_arn=Arn("arn:aws:s3:::test-bucket"),
            kms_key_arn=Arn("arn:aws:kms:ap-southeast-2:123456789012:key/test-key"),
        ),
        ca=CA(
            stack_name="iam-ra-test-rootca",
            mode=CAMode.SELF_SIGNED,
            trust_anchor_arn=Arn(
                "arn:aws:rolesanywhere:ap-southeast-2:123456789012:trust-anchor/test-anchor"
            ),
        ),
        roles={
            "admin": Role(
                stack_name="iam-ra-test-role-admin",
                role_arn=Arn("arn:aws:iam::123456789012:role/iam-ra-test-admin"),
                profile_arn=Arn(
                    "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/test-profile"
                ),
                policies=(Arn("arn:aws:iam::aws:policy/AdministratorAccess"),),
            )
        },
        hosts={
            "web1": Host(
                stack_name="iam-ra-test-host-web1",
                hostname="web1",
                role_name="admin",
                certificate_secret_arn=Arn(
                    "arn:aws:secretsmanager:ap-southeast-2:123456789012:secret:test-cert"
                ),
                private_key_secret_arn=Arn(
                    "arn:aws:secretsmanager:ap-southeast-2:123456789012:secret:test-key"
                ),
            )
        },
    )


class TestStateSerialization:
    """Tests for State JSON serialization/deserialization."""

    def test_state_to_json(self, sample_state: State) -> None:
        json_str = sample_state.to_json()

        # Should be valid JSON
        data = json.loads(json_str)

        assert data["namespace"] == "test"
        assert data["region"] == "ap-southeast-2"
        assert data["init"]["stack_name"] == "iam-ra-test-init"
        assert data["ca"]["mode"] == "self-signed"
        assert "admin" in data["roles"]
        assert "web1" in data["hosts"]

    def test_state_from_json(self, sample_state: State) -> None:
        json_str = sample_state.to_json()
        restored = State.from_json(json_str)

        assert restored.namespace == sample_state.namespace
        assert restored.region == sample_state.region
        assert restored.is_initialized is True

        assert restored.init is not None
        assert restored.init.stack_name == sample_state.init.stack_name
        assert isinstance(restored.init.bucket_arn, Arn)

        assert restored.ca is not None
        assert restored.ca.mode == CAMode.SELF_SIGNED
        assert isinstance(restored.ca.trust_anchor_arn, Arn)

        assert "admin" in restored.roles
        assert isinstance(restored.roles["admin"].role_arn, Arn)

        assert "web1" in restored.hosts
        assert restored.hosts["web1"].hostname == "web1"

    def test_state_roundtrip_preserves_data(self, sample_state: State) -> None:
        """Roundtrip serialization should preserve all data."""
        json_str = sample_state.to_json()
        restored = State.from_json(json_str)
        json_str_2 = restored.to_json()

        # JSON should be identical
        assert json.loads(json_str) == json.loads(json_str_2)


class TestStateLoad:
    """Tests for state load function."""

    def test_load_nonexistent_namespace_returns_none(self, aws_clients) -> None:
        ssm, s3 = aws_clients

        result = state_module.load(ssm, s3, "nonexistent", skip_cache=True)

        assert isinstance(result, Ok)
        assert result.value is None

    def test_load_existing_state(self, aws_clients, sample_state: State) -> None:
        ssm, s3 = aws_clients
        namespace = sample_state.namespace
        bucket = "test-bucket"
        key = f"{namespace}/state.json"

        # Store state in S3
        s3.put_object(Bucket=bucket, Key=key, Body=sample_state.to_json().encode("utf-8"))

        # Set SSM pointer
        ssm.put_parameter(
            Name=f"/iam-ra/{namespace}/state-location",
            Value=f"s3://{bucket}/{key}",
            Type="String",
        )

        result = state_module.load(ssm, s3, namespace, skip_cache=True)

        assert isinstance(result, Ok)
        assert result.value is not None
        assert result.value.namespace == namespace
        assert result.value.is_initialized is True


class TestStateSave:
    """Tests for state save function."""

    def test_save_state(self, aws_clients, sample_state: State) -> None:
        ssm, s3 = aws_clients

        result = state_module.save(ssm, s3, sample_state)

        assert isinstance(result, Ok)

        # Verify SSM parameter was created
        param = ssm.get_parameter(Name=f"/iam-ra/{sample_state.namespace}/state-location")
        s3_uri = param["Parameter"]["Value"]
        assert s3_uri == f"s3://test-bucket/{sample_state.namespace}/state.json"

        # Verify S3 object was created
        response = s3.get_object(Bucket="test-bucket", Key=f"{sample_state.namespace}/state.json")
        stored_json = response["Body"].read().decode("utf-8")
        stored_state = State.from_json(stored_json)

        assert stored_state.namespace == sample_state.namespace
        assert stored_state.is_initialized is True

    def test_save_without_init_fails(self, aws_clients) -> None:
        ssm, s3 = aws_clients

        state = State(namespace="test", region="ap-southeast-2", version="0.1.0")

        result = state_module.save(ssm, s3, state)

        assert isinstance(result, Err)
        assert "init" in result.error.reason.lower() or "bucket" in result.error.reason.lower()


class TestStateCache:
    """Tests for state caching."""

    def test_invalidate_cache(self, aws_clients, temp_cache_dir: Path, sample_state: State) -> None:
        ssm, s3 = aws_clients
        namespace = sample_state.namespace

        # First save (which updates cache)
        state_module.save(ssm, s3, sample_state)

        # Verify cache exists
        cache_path = temp_cache_dir / namespace / "state.json"
        assert cache_path.exists()

        # Invalidate
        state_module.invalidate_cache(namespace)

        # Verify cache is gone
        assert not cache_path.exists()
