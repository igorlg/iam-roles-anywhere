"""Tests for workflows/migrate.py - v1 to v2 state migration.

Phase 6: Migrate v1 state (single CA) to v2 state (scoped CAs).

Migration steps:
1. State JSON: from_json auto-migrates, re-save writes v2 format
2. S3: copy {ns}/ca/certificate.pem -> {ns}/scopes/default/ca/certificate.pem
3. Local: move {ns}/ca-private-key.pem -> {ns}/scopes/default/ca-private-key.pem
4. Role CFN stacks: update with new template adding TrustAnchorArn parameter
5. Re-save state in v2 format

Tests mock the role operations layer (CFN deployment) since moto has
limited support for the complex CloudFormation templates.
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
from moto import mock_aws

from iam_ra_cli.lib import state as state_module
from iam_ra_cli.lib.aws import AwsContext
from iam_ra_cli.lib.errors import NotInitializedError
from iam_ra_cli.lib.result import Err, Ok
from iam_ra_cli.models import Arn
from iam_ra_cli.operations.role import RoleResult
from iam_ra_cli.workflows.migrate import MigrateResult, migrate


# =============================================================================
# Fixtures
# =============================================================================

SAMPLE_CA_CERT = "-----BEGIN CERTIFICATE-----\nMIIBfake\n-----END CERTIFICATE-----"
SAMPLE_CA_KEY = "-----BEGIN EC PRIVATE KEY-----\nMHcfake\n-----END EC PRIVATE KEY-----"


@pytest.fixture
def aws_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "ap-southeast-2")


@pytest.fixture
def temp_xdg_dirs(monkeypatch: pytest.MonkeyPatch):
    with tempfile.TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        data_dir = base / "data"
        data_dir.mkdir()
        monkeypatch.setenv("XDG_DATA_HOME", str(data_dir))

        def mock_state_cache_path(namespace: str) -> Path:
            return base / "cache" / namespace / "state.json"

        monkeypatch.setattr("iam_ra_cli.lib.state.paths.state_cache_path", mock_state_cache_path)
        yield base


def make_v1_state_json(namespace: str = "test", with_roles: bool = True) -> str:
    """Create a v1-format state JSON (single 'ca' key, roles without scope)."""
    state = {
        "namespace": namespace,
        "region": "ap-southeast-2",
        "version": "1.0.0",
        "init": {
            "stack_name": f"iam-ra-{namespace}-init",
            "bucket_arn": "arn:aws:s3:::test-bucket",
            "kms_key_arn": "arn:aws:kms:ap-southeast-2:123456789012:key/test-key",
        },
        "ca": {
            "stack_name": f"iam-ra-{namespace}-rootca",
            "mode": "self-signed",
            "trust_anchor_arn": "arn:aws:rolesanywhere:ap-southeast-2:123456789012:trust-anchor/ta-v1",
            "pca_arn": None,
        },
        "roles": {},
        "hosts": {},
        "k8s_clusters": {},
        "k8s_workloads": {},
    }
    if with_roles:
        state["roles"] = {
            "admin": {
                "stack_name": f"iam-ra-{namespace}-role-admin",
                "role_arn": "arn:aws:iam::123456789012:role/admin",
                "profile_arn": "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/admin-profile",
                "policies": [],
                # NOTE: no "scope" field -- this is v1
            },
        }
    return json.dumps(state, indent=2)


def setup_v1_in_aws(
    ctx: AwsContext,
    namespace: str = "test",
    with_roles: bool = True,
    with_local_key: bool = True,
) -> None:
    """Set up a v1 environment in mocked AWS."""
    bucket = "test-bucket"
    state_json = make_v1_state_json(namespace, with_roles)

    ctx.s3.create_bucket(
        Bucket=bucket,
        CreateBucketConfiguration={"LocationConstraint": "ap-southeast-2"},
    )

    # v1 state JSON
    ctx.s3.put_object(Bucket=bucket, Key=f"{namespace}/state.json", Body=state_json.encode())

    # v1 CA cert at OLD path
    ctx.s3.put_object(
        Bucket=bucket,
        Key=f"{namespace}/ca/certificate.pem",
        Body=SAMPLE_CA_CERT.encode(),
    )

    # SSM pointer
    ctx.ssm.put_parameter(
        Name=f"/iam-ra/{namespace}/state-location",
        Value=f"s3://{bucket}/{namespace}/state.json",
        Type="String",
    )


def setup_v1_local_key(data_dir: Path, namespace: str = "test") -> Path:
    """Create v1 local CA key at the old path."""
    import iam_ra_cli.lib.paths as paths_mod

    old_key_dir = paths_mod.data_dir() / namespace
    old_key_dir.mkdir(parents=True, exist_ok=True)
    old_key_path = old_key_dir / "ca-private-key.pem"
    old_key_path.write_text(SAMPLE_CA_KEY)
    return old_key_path


# =============================================================================
# Tests: State Migration
# =============================================================================


class TestMigrateState:
    """State JSON should be migrated from v1 to v2 format."""

    def test_saves_state_in_v2_format(self, aws_credentials, temp_xdg_dirs) -> None:
        """After migration, saved state should have 'cas' dict, not 'ca'."""
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            setup_v1_in_aws(ctx, with_roles=False)
            setup_v1_local_key(temp_xdg_dirs / "data")

            with patch(
                "iam_ra_cli.workflows.migrate.update_role_stack",
                return_value=Ok(None),
            ):
                result = migrate(ctx, "test")

            assert isinstance(result, Ok)

            # Read raw state from S3 and verify v2 format
            response = ctx.s3.get_object(Bucket="test-bucket", Key="test/state.json")
            raw = json.loads(response["Body"].read().decode())
            assert "cas" in raw
            assert "ca" not in raw
            assert "default" in raw["cas"]

    def test_preserves_ca_stack_name(self, aws_credentials, temp_xdg_dirs) -> None:
        """The CA stack name from v1 should be preserved (not renamed)."""
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            setup_v1_in_aws(ctx, with_roles=False)
            setup_v1_local_key(temp_xdg_dirs / "data")

            with patch(
                "iam_ra_cli.workflows.migrate.update_role_stack",
                return_value=Ok(None),
            ):
                result = migrate(ctx, "test")

            assert isinstance(result, Ok)

            response = ctx.s3.get_object(Bucket="test-bucket", Key="test/state.json")
            raw = json.loads(response["Body"].read().decode())
            assert raw["cas"]["default"]["stack_name"] == "iam-ra-test-rootca"

    def test_roles_get_default_scope(self, aws_credentials, temp_xdg_dirs) -> None:
        """After migration, existing roles should have scope='default'."""
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            setup_v1_in_aws(ctx, with_roles=True)
            setup_v1_local_key(temp_xdg_dirs / "data")

            with patch(
                "iam_ra_cli.workflows.migrate.update_role_stack",
                return_value=Ok(None),
            ):
                result = migrate(ctx, "test")

            assert isinstance(result, Ok)

            response = ctx.s3.get_object(Bucket="test-bucket", Key="test/state.json")
            raw = json.loads(response["Body"].read().decode())
            assert raw["roles"]["admin"]["scope"] == "default"


# =============================================================================
# Tests: S3 Path Migration
# =============================================================================


class TestMigrateS3Paths:
    """S3 CA cert should be copied from old path to new scoped path."""

    def test_copies_ca_cert_to_scoped_path(self, aws_credentials, temp_xdg_dirs) -> None:
        """CA cert should exist at the new scoped path after migration."""
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            setup_v1_in_aws(ctx, with_roles=False)
            setup_v1_local_key(temp_xdg_dirs / "data")

            with patch(
                "iam_ra_cli.workflows.migrate.update_role_stack",
                return_value=Ok(None),
            ):
                migrate(ctx, "test")

            # New scoped path should exist
            response = ctx.s3.get_object(
                Bucket="test-bucket",
                Key="test/scopes/default/ca/certificate.pem",
            )
            cert = response["Body"].read().decode()
            assert cert == SAMPLE_CA_CERT

    def test_deletes_old_ca_cert(self, aws_credentials, temp_xdg_dirs) -> None:
        """Old CA cert path should be deleted after migration."""
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            setup_v1_in_aws(ctx, with_roles=False)
            setup_v1_local_key(temp_xdg_dirs / "data")

            with patch(
                "iam_ra_cli.workflows.migrate.update_role_stack",
                return_value=Ok(None),
            ):
                migrate(ctx, "test")

            # Old path should be gone
            from botocore.exceptions import ClientError

            with pytest.raises(ClientError):
                ctx.s3.get_object(Bucket="test-bucket", Key="test/ca/certificate.pem")

    def test_skips_s3_if_already_migrated(self, aws_credentials, temp_xdg_dirs) -> None:
        """If new scoped path already exists and old doesn't, skip S3 migration."""
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            setup_v1_in_aws(ctx, with_roles=False)
            setup_v1_local_key(temp_xdg_dirs / "data")

            # Pre-place cert at new path and remove old
            ctx.s3.put_object(
                Bucket="test-bucket",
                Key="test/scopes/default/ca/certificate.pem",
                Body=SAMPLE_CA_CERT.encode(),
            )
            ctx.s3.delete_object(Bucket="test-bucket", Key="test/ca/certificate.pem")

            with patch(
                "iam_ra_cli.workflows.migrate.update_role_stack",
                return_value=Ok(None),
            ):
                result = migrate(ctx, "test")

            assert isinstance(result, Ok)
            assert not result.value.s3_migrated


# =============================================================================
# Tests: Local Key Migration
# =============================================================================


class TestMigrateLocalKey:
    """Local CA private key should be moved from old path to new scoped path."""

    def test_moves_key_to_scoped_path(self, aws_credentials, temp_xdg_dirs) -> None:
        """Key should exist at new scoped path after migration."""
        import iam_ra_cli.lib.paths as paths_mod

        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            setup_v1_in_aws(ctx, with_roles=False)
            old_path = setup_v1_local_key(temp_xdg_dirs / "data")

            with patch(
                "iam_ra_cli.workflows.migrate.update_role_stack",
                return_value=Ok(None),
            ):
                migrate(ctx, "test")

            new_path = paths_mod.data_dir() / "test" / "scopes" / "default" / "ca-private-key.pem"
            assert new_path.exists()
            assert new_path.read_text() == SAMPLE_CA_KEY

    def test_deletes_old_key(self, aws_credentials, temp_xdg_dirs) -> None:
        """Old key path should be deleted after migration."""
        import iam_ra_cli.lib.paths as paths_mod

        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            setup_v1_in_aws(ctx, with_roles=False)
            old_path = setup_v1_local_key(temp_xdg_dirs / "data")

            with patch(
                "iam_ra_cli.workflows.migrate.update_role_stack",
                return_value=Ok(None),
            ):
                migrate(ctx, "test")

            assert not old_path.exists()

    def test_skips_local_if_already_migrated(self, aws_credentials, temp_xdg_dirs) -> None:
        """If new path exists and old doesn't, skip local migration."""
        import iam_ra_cli.lib.paths as paths_mod

        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            setup_v1_in_aws(ctx, with_roles=False)
            # Don't create old key, create new one instead
            new_key_dir = paths_mod.data_dir() / "test" / "scopes" / "default"
            new_key_dir.mkdir(parents=True)
            (new_key_dir / "ca-private-key.pem").write_text(SAMPLE_CA_KEY)

            with patch(
                "iam_ra_cli.workflows.migrate.update_role_stack",
                return_value=Ok(None),
            ):
                result = migrate(ctx, "test")

            assert isinstance(result, Ok)
            assert not result.value.local_key_migrated


# =============================================================================
# Tests: Role Stack Updates
# =============================================================================


class TestMigrateRoleStacks:
    """Role CFN stacks should be updated with TrustAnchorArn parameter."""

    def test_updates_each_role_stack(self, aws_credentials, temp_xdg_dirs) -> None:
        """Each role should have its CFN stack updated."""
        captured_calls = []

        def fake_update(ctx, namespace, name, trust_anchor_arn, policies, scope):
            captured_calls.append(
                {
                    "name": name,
                    "trust_anchor_arn": trust_anchor_arn,
                    "scope": scope,
                }
            )
            return Ok(None)

        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            setup_v1_in_aws(ctx, with_roles=True)
            setup_v1_local_key(temp_xdg_dirs / "data")

            with patch(
                "iam_ra_cli.workflows.migrate.update_role_stack",
                side_effect=fake_update,
            ):
                result = migrate(ctx, "test")

            assert isinstance(result, Ok)
            assert len(captured_calls) == 1
            assert captured_calls[0]["name"] == "admin"
            assert "ta-v1" in captured_calls[0]["trust_anchor_arn"]
            assert captured_calls[0]["scope"] == "default"

    def test_passes_correct_trust_anchor(self, aws_credentials, temp_xdg_dirs) -> None:
        """Should pass the default scope's trust anchor ARN to role stack update."""
        captured_ta = {}

        def fake_update(ctx, namespace, name, trust_anchor_arn, policies, scope):
            captured_ta[name] = trust_anchor_arn
            return Ok(None)

        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            setup_v1_in_aws(ctx, with_roles=True)
            setup_v1_local_key(temp_xdg_dirs / "data")

            with patch(
                "iam_ra_cli.workflows.migrate.update_role_stack",
                side_effect=fake_update,
            ):
                migrate(ctx, "test")

            assert (
                captured_ta["admin"]
                == "arn:aws:rolesanywhere:ap-southeast-2:123456789012:trust-anchor/ta-v1"
            )

    def test_reports_updated_roles(self, aws_credentials, temp_xdg_dirs) -> None:
        """MigrateResult should list which roles were updated."""
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            setup_v1_in_aws(ctx, with_roles=True)
            setup_v1_local_key(temp_xdg_dirs / "data")

            with patch(
                "iam_ra_cli.workflows.migrate.update_role_stack",
                return_value=Ok(None),
            ):
                result = migrate(ctx, "test")

            assert isinstance(result, Ok)
            assert "admin" in result.value.roles_updated

    def test_no_roles_to_update(self, aws_credentials, temp_xdg_dirs) -> None:
        """Should succeed with empty roles_updated when no roles exist."""
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            setup_v1_in_aws(ctx, with_roles=False)
            setup_v1_local_key(temp_xdg_dirs / "data")

            with patch(
                "iam_ra_cli.workflows.migrate.update_role_stack",
                return_value=Ok(None),
            ):
                result = migrate(ctx, "test")

            assert isinstance(result, Ok)
            assert result.value.roles_updated == []


# =============================================================================
# Tests: Idempotency
# =============================================================================


class TestMigrateIdempotency:
    """Running migrate twice should produce the same result."""

    def test_second_run_is_noop(self, aws_credentials, temp_xdg_dirs) -> None:
        """Second migration should succeed with all flags False."""
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            setup_v1_in_aws(ctx, with_roles=False)
            setup_v1_local_key(temp_xdg_dirs / "data")

            with patch(
                "iam_ra_cli.workflows.migrate.update_role_stack",
                return_value=Ok(None),
            ):
                result1 = migrate(ctx, "test")
                state_module.invalidate_cache("test")
                result2 = migrate(ctx, "test")

            assert isinstance(result1, Ok)
            assert isinstance(result2, Ok)
            # Second run: nothing left to migrate
            assert not result2.value.s3_migrated
            assert not result2.value.local_key_migrated


# =============================================================================
# Tests: Error Cases
# =============================================================================


class TestMigrateErrors:
    """Error handling for migrate workflow."""

    def test_fails_if_not_initialized(self, aws_credentials, temp_xdg_dirs) -> None:
        """Should fail if namespace is not initialized."""
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")

            result = migrate(ctx, "nonexistent")

            assert isinstance(result, Err)
            assert isinstance(result.error, NotInitializedError)
