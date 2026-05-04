"""Tests for lib/state.py - State management with SSM and S3."""

import json
import tempfile
from pathlib import Path

import pytest
from moto import mock_aws

from iam_ra_cli.lib import state as state_module
from iam_ra_cli.lib.result import Err, Ok
from iam_ra_cli.models import CA, Arn, CAMode, Host, Init, NamespaceInfo, Role, State


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
        namespace_info=NamespaceInfo(
            account_id="123456789012",
            region="ap-southeast-2",
        ),
        init=Init(
            stack_name="iam-ra-test-init",
            bucket_arn=Arn("arn:aws:s3:::test-bucket"),
            kms_key_arn=Arn("arn:aws:kms:ap-southeast-2:123456789012:key/test-key"),
        ),
        cas={
            "default": CA(
                stack_name="iam-ra-test-rootca",
                mode=CAMode.SELF_SIGNED,
                trust_anchor_arn=Arn(
                    "arn:aws:rolesanywhere:ap-southeast-2:123456789012:trust-anchor/test-anchor"
                ),
                account_id="123456789012",
            ),
        },
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
                role_names=("admin",),
                scope="default",
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
        assert data["cas"]["default"]["mode"] == "self-signed"
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


# =============================================================================
# Loading old-version state files
#
# Users who upgrade iam-ra will have existing state files on S3 / in local
# cache from previous versions. load() must transparently migrate them so no
# manual `iam-ra migrate` is needed for the simple read path.
#
# These fixtures are raw JSON strings (the on-disk shape of each version)
# rather than constructed Python objects. That lets us test exactly what
# comes out of S3 for a real upgrader.
# =============================================================================


@pytest.fixture
def v1_state_json() -> str:
    """Raw v1 state JSON - had a singular `ca` field (not `cas` dict), Host
    had `role_name: str`, no Host.scope, no CA.account_id, no namespace_info.

    Represents what an old iam-ra 1.x install would have in S3.
    """
    return json.dumps(
        {
            "namespace": "legacy-v1",
            "region": "ap-southeast-2",
            "version": "1.0.0",
            "init": {
                "stack_name": "iam-ra-legacy-v1-init",
                "bucket_arn": "arn:aws:s3:::legacy-v1-bucket",
                "kms_key_arn": "arn:aws:kms:ap-southeast-2:111122223333:key/v1-key",
            },
            "ca": {
                "stack_name": "iam-ra-legacy-v1-rootca",
                "mode": "self-signed",
                "trust_anchor_arn": (
                    "arn:aws:rolesanywhere:ap-southeast-2:111122223333:trust-anchor/v1-ta"
                ),
            },
            "roles": {
                "admin": {
                    "stack_name": "iam-ra-legacy-v1-role-admin",
                    "role_arn": "arn:aws:iam::111122223333:role/admin",
                    "profile_arn": (
                        "arn:aws:rolesanywhere:ap-southeast-2:111122223333:profile/admin"
                    ),
                    "policies": [],
                },
            },
            "hosts": {
                "legacy-host": {
                    "stack_name": "iam-ra-legacy-v1-host-legacy-host",
                    "hostname": "legacy-host",
                    "role_name": "admin",
                    "certificate_secret_arn": (
                        "arn:aws:secretsmanager:ap-southeast-2:111122223333:secret:cert-v1"
                    ),
                    "private_key_secret_arn": (
                        "arn:aws:secretsmanager:ap-southeast-2:111122223333:secret:key-v1"
                    ),
                },
            },
        }
    )


@pytest.fixture
def v2_state_json() -> str:
    """Raw v2 state JSON - has per-scope `cas` dict + Role.scope, but still
    has Host.role_name (str), no Host.scope, no CA.account_id, no
    namespace_info.

    Represents what an iam-ra 2.x install (before this PR) would have in S3.

    Note: bucket_arn uses `test-bucket` to match the mocked S3 bucket in
    aws_clients, so save() round-trips work in tests.
    """
    return json.dumps(
        {
            "namespace": "legacy-v2",
            "region": "ap-southeast-2",
            "version": "2.4.2",
            "init": {
                "stack_name": "iam-ra-legacy-v2-init",
                "bucket_arn": "arn:aws:s3:::test-bucket",
                "kms_key_arn": "arn:aws:kms:ap-southeast-2:444455556666:key/v2-key",
            },
            "cas": {
                "default": {
                    "stack_name": "iam-ra-legacy-v2-ca-default",
                    "mode": "self-signed",
                    "trust_anchor_arn": (
                        "arn:aws:rolesanywhere:ap-southeast-2:444455556666:trust-anchor/v2-ta"
                    ),
                },
                "cert-manager": {
                    "stack_name": "iam-ra-legacy-v2-ca-cert-manager",
                    "mode": "self-signed",
                    "trust_anchor_arn": (
                        "arn:aws:rolesanywhere:ap-southeast-2:444455556666:trust-anchor/v2-ta-cm"
                    ),
                },
            },
            "roles": {
                "admin": {
                    "stack_name": "iam-ra-legacy-v2-role-admin",
                    "role_arn": "arn:aws:iam::444455556666:role/admin",
                    "profile_arn": (
                        "arn:aws:rolesanywhere:ap-southeast-2:444455556666:profile/admin"
                    ),
                    "policies": [],
                    "scope": "default",
                },
                "cm-role": {
                    "stack_name": "iam-ra-legacy-v2-role-cm-role",
                    "role_arn": "arn:aws:iam::444455556666:role/cm-role",
                    "profile_arn": (
                        "arn:aws:rolesanywhere:ap-southeast-2:444455556666:profile/cm-role"
                    ),
                    "policies": [],
                    "scope": "cert-manager",
                },
            },
            "hosts": {
                "default-host": {
                    "stack_name": "iam-ra-legacy-v2-host-default-host",
                    "hostname": "default-host",
                    "role_name": "admin",
                    "certificate_secret_arn": (
                        "arn:aws:secretsmanager:ap-southeast-2:444455556666:secret:cert-default"
                    ),
                    "private_key_secret_arn": (
                        "arn:aws:secretsmanager:ap-southeast-2:444455556666:secret:key-default"
                    ),
                },
                "cm-host": {
                    "stack_name": "iam-ra-legacy-v2-host-cm-host",
                    "hostname": "cm-host",
                    "role_name": "cm-role",
                    "certificate_secret_arn": (
                        "arn:aws:secretsmanager:ap-southeast-2:444455556666:secret:cert-cm"
                    ),
                    "private_key_secret_arn": (
                        "arn:aws:secretsmanager:ap-southeast-2:444455556666:secret:key-cm"
                    ),
                },
            },
        }
    )


def _put_raw_state(s3, ssm, namespace: str, raw_json: str) -> None:
    """Place a pre-existing state file in S3 and point SSM at it."""
    bucket = "test-bucket"
    key = f"{namespace}/state.json"
    s3.put_object(Bucket=bucket, Key=key, Body=raw_json.encode("utf-8"))
    ssm.put_parameter(
        Name=f"/iam-ra/{namespace}/state-location",
        Value=f"s3://{bucket}/{key}",
        Type="String",
    )


class TestLoadV1State:
    """load() must transparently migrate v1 state to current shape."""

    def test_load_v1_returns_ok(self, aws_clients, v1_state_json: str) -> None:
        ssm, s3 = aws_clients
        _put_raw_state(s3, ssm, "legacy-v1", v1_state_json)

        result = state_module.load(ssm, s3, "legacy-v1", skip_cache=True)

        assert isinstance(result, Ok)
        assert result.value is not None

    def test_load_v1_migrates_ca_to_cas(self, aws_clients, v1_state_json: str) -> None:
        """v1 `ca` singular -> v2+ `cas` dict keyed by scope."""
        ssm, s3 = aws_clients
        _put_raw_state(s3, ssm, "legacy-v1", v1_state_json)

        result = state_module.load(ssm, s3, "legacy-v1", skip_cache=True)

        assert isinstance(result, Ok) and result.value is not None
        assert "default" in result.value.cas
        assert result.value.cas["default"].stack_name == "iam-ra-legacy-v1-rootca"

    def test_load_v1_migrates_host_role_name(
        self, aws_clients, v1_state_json: str
    ) -> None:
        """v1 Host had role_name (str); v3 has role_names (tuple)."""
        ssm, s3 = aws_clients
        _put_raw_state(s3, ssm, "legacy-v1", v1_state_json)

        result = state_module.load(ssm, s3, "legacy-v1", skip_cache=True)

        assert isinstance(result, Ok) and result.value is not None
        host = result.value.hosts["legacy-host"]
        assert host.role_names == ("admin",)
        assert host.scope == "default"

    def test_load_v1_backfills_namespace_info(
        self, aws_clients, v1_state_json: str
    ) -> None:
        """NamespaceInfo should be derived from init.kms_key_arn.account."""
        ssm, s3 = aws_clients
        _put_raw_state(s3, ssm, "legacy-v1", v1_state_json)

        result = state_module.load(ssm, s3, "legacy-v1", skip_cache=True)

        assert isinstance(result, Ok) and result.value is not None
        assert result.value.namespace_info is not None
        assert result.value.namespace_info.account_id == "111122223333"

    def test_load_v1_backfills_ca_account_id(
        self, aws_clients, v1_state_json: str
    ) -> None:
        """CA.account_id should be derived from trust_anchor_arn.account."""
        ssm, s3 = aws_clients
        _put_raw_state(s3, ssm, "legacy-v1", v1_state_json)

        result = state_module.load(ssm, s3, "legacy-v1", skip_cache=True)

        assert isinstance(result, Ok) and result.value is not None
        assert result.value.cas["default"].account_id == "111122223333"


class TestLoadV2State:
    """load() must transparently migrate v2 state to current shape.

    This is the main real-world upgrade path - v2.x is the immediate
    predecessor.
    """

    def test_load_v2_returns_ok(self, aws_clients, v2_state_json: str) -> None:
        ssm, s3 = aws_clients
        _put_raw_state(s3, ssm, "legacy-v2", v2_state_json)

        result = state_module.load(ssm, s3, "legacy-v2", skip_cache=True)

        assert isinstance(result, Ok)
        assert result.value is not None

    def test_load_v2_preserves_multi_scope_cas(
        self, aws_clients, v2_state_json: str
    ) -> None:
        """v2 already had per-scope cas; verify it comes through intact."""
        ssm, s3 = aws_clients
        _put_raw_state(s3, ssm, "legacy-v2", v2_state_json)

        result = state_module.load(ssm, s3, "legacy-v2", skip_cache=True)

        assert isinstance(result, Ok) and result.value is not None
        assert set(result.value.cas.keys()) == {"default", "cert-manager"}

    def test_load_v2_host_scope_derives_from_role(
        self, aws_clients, v2_state_json: str
    ) -> None:
        """Host.scope was implicit in v2 (via role.scope). v3 materialises it."""
        ssm, s3 = aws_clients
        _put_raw_state(s3, ssm, "legacy-v2", v2_state_json)

        result = state_module.load(ssm, s3, "legacy-v2", skip_cache=True)

        assert isinstance(result, Ok) and result.value is not None
        assert result.value.hosts["default-host"].scope == "default"
        assert result.value.hosts["cm-host"].scope == "cert-manager"

    def test_load_v2_backfills_per_scope_ca_account_id(
        self, aws_clients, v2_state_json: str
    ) -> None:
        ssm, s3 = aws_clients
        _put_raw_state(s3, ssm, "legacy-v2", v2_state_json)

        result = state_module.load(ssm, s3, "legacy-v2", skip_cache=True)

        assert isinstance(result, Ok) and result.value is not None
        # Both scopes' CAs are in the same AWS account; both should get the
        # account_id backfilled from their (different) trust anchor ARNs.
        assert result.value.cas["default"].account_id == "444455556666"
        assert result.value.cas["cert-manager"].account_id == "444455556666"

    def test_load_v2_backfills_namespace_info(
        self, aws_clients, v2_state_json: str
    ) -> None:
        ssm, s3 = aws_clients
        _put_raw_state(s3, ssm, "legacy-v2", v2_state_json)

        result = state_module.load(ssm, s3, "legacy-v2", skip_cache=True)

        assert isinstance(result, Ok) and result.value is not None
        assert result.value.namespace_info is not None
        assert result.value.namespace_info.account_id == "444455556666"
        assert result.value.namespace_info.region == "ap-southeast-2"

    def test_load_v2_host_role_names_tuple(
        self, aws_clients, v2_state_json: str
    ) -> None:
        """v2 Host.role_name (str) becomes v3 Host.role_names (tuple)."""
        ssm, s3 = aws_clients
        _put_raw_state(s3, ssm, "legacy-v2", v2_state_json)

        result = state_module.load(ssm, s3, "legacy-v2", skip_cache=True)

        assert isinstance(result, Ok) and result.value is not None
        assert result.value.hosts["default-host"].role_names == ("admin",)
        assert result.value.hosts["cm-host"].role_names == ("cm-role",)

    def test_load_v2_then_save_writes_v3_shape(
        self, aws_clients, v2_state_json: str
    ) -> None:
        """After load-from-v2 + save, S3 should now hold a v3-shaped state
        (role_names tuple, explicit scope, account_id, namespace_info).
        Confirms migration is persisted back to S3 rather than being a
        read-time-only transform."""
        ssm, s3 = aws_clients
        _put_raw_state(s3, ssm, "legacy-v2", v2_state_json)

        loaded = state_module.load(ssm, s3, "legacy-v2", skip_cache=True)
        assert isinstance(loaded, Ok) and loaded.value is not None

        save_result = state_module.save(ssm, s3, loaded.value)
        assert isinstance(save_result, Ok)

        # Read the raw JSON from S3 and verify v3 fields are present
        obj = s3.get_object(Bucket="test-bucket", Key="legacy-v2/state.json")
        raw = json.loads(obj["Body"].read().decode("utf-8"))

        assert raw["namespace_info"]["account_id"] == "444455556666"
        assert raw["cas"]["default"]["account_id"] == "444455556666"
        default_host = raw["hosts"]["default-host"]
        assert default_host["role_names"] == ["admin"]
        assert default_host["scope"] == "default"
        # Old fields should no longer be present after migration + resave
        assert "role_name" not in default_host
