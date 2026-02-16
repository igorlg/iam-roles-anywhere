"""Tests for workflows/ca.py - CA scope management workflows.

These tests focus on state management and validation logic,
mocking CloudFormation operations since moto has limited support
for the complex templates used in iam-ra.
"""

import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
from moto import mock_aws

from iam_ra_cli.lib.aws import AwsContext
from iam_ra_cli.lib.errors import (
    CAScopeAlreadyExistsError,
    CAScopeNotFoundError,
    NotInitializedError,
)
from iam_ra_cli.lib.result import Err, Ok
from iam_ra_cli.models import CA, Arn, CAMode, Init, State
from iam_ra_cli.operations.ca import SelfSignedCAResult
from iam_ra_cli.workflows.ca import delete_scope, list_cas, setup_ca


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def aws_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    """Mock AWS credentials."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "ap-southeast-2")


@pytest.fixture
def temp_xdg_dirs(monkeypatch: pytest.MonkeyPatch):
    """Create temporary XDG directories."""
    with tempfile.TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)

        def mock_state_cache_path(namespace: str) -> Path:
            return base / "cache" / namespace / "state.json"

        monkeypatch.setattr("iam_ra_cli.lib.state.paths.state_cache_path", mock_state_cache_path)
        yield base


@pytest.fixture
def initialized_state() -> State:
    """Create an initialized state with default CA."""
    return State(
        namespace="test",
        region="ap-southeast-2",
        version="2.0.0",
        init=Init(
            stack_name="iam-ra-test-init",
            bucket_arn=Arn("arn:aws:s3:::test-bucket"),
            kms_key_arn=Arn("arn:aws:kms:ap-southeast-2:123456789012:key/test-key"),
        ),
        cas={
            "default": CA(
                stack_name="iam-ra-test-ca-default",
                mode=CAMode.SELF_SIGNED,
                trust_anchor_arn=Arn(
                    "arn:aws:rolesanywhere:ap-southeast-2:123456789012:trust-anchor/ta-default"
                ),
            ),
        },
    )


@pytest.fixture
def initialized_state_no_ca() -> State:
    """Create an initialized state without any CA scopes."""
    return State(
        namespace="test",
        region="ap-southeast-2",
        version="2.0.0",
        init=Init(
            stack_name="iam-ra-test-init",
            bucket_arn=Arn("arn:aws:s3:::test-bucket"),
            kms_key_arn=Arn("arn:aws:kms:ap-southeast-2:123456789012:key/test-key"),
        ),
    )


def setup_state_in_aws(ctx: AwsContext, state: State) -> None:
    """Helper to set up state in mocked AWS services."""
    bucket = "test-bucket"
    key = f"{state.namespace}/state.json"

    ctx.s3.create_bucket(
        Bucket=bucket,
        CreateBucketConfiguration={"LocationConstraint": "ap-southeast-2"},
    )
    ctx.s3.put_object(Bucket=bucket, Key=key, Body=state.to_json().encode("utf-8"))
    ctx.ssm.put_parameter(
        Name=f"/iam-ra/{state.namespace}/state-location",
        Value=f"s3://{bucket}/{key}",
        Type="String",
    )


# =============================================================================
# setup_ca tests
# =============================================================================


class TestSetupCA:
    """Tests for setup_ca workflow."""

    def test_fails_when_not_initialized(self, aws_credentials, temp_xdg_dirs) -> None:
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            result = setup_ca(ctx, "test", scope="cert-manager")
            assert isinstance(result, Err)
            assert isinstance(result.error, NotInitializedError)

    def test_fails_when_scope_already_exists(
        self, aws_credentials, temp_xdg_dirs, initialized_state: State
    ) -> None:
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            setup_state_in_aws(ctx, initialized_state)

            result = setup_ca(ctx, "test", scope="default")
            assert isinstance(result, Err)
            assert isinstance(result.error, CAScopeAlreadyExistsError)
            assert result.error.scope == "default"

    def test_creates_new_scope(
        self, aws_credentials, temp_xdg_dirs, initialized_state: State
    ) -> None:
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            setup_state_in_aws(ctx, initialized_state)

            mock_ca_result = SelfSignedCAResult(
                stack_name="iam-ra-test-ca-cert-manager",
                trust_anchor_arn=Arn(
                    "arn:aws:rolesanywhere:ap-southeast-2:123456789012:trust-anchor/ta-cm"
                ),
                cert_s3_key="test/scopes/cert-manager/ca/certificate.pem",
                local_key_path=Path("/tmp/fake"),
            )

            with patch(
                "iam_ra_cli.workflows.ca.create_self_signed_ca",
                return_value=Ok(mock_ca_result),
            ):
                result = setup_ca(ctx, "test", scope="cert-manager")

            assert isinstance(result, Ok)
            assert result.value.mode == CAMode.SELF_SIGNED
            assert result.value.stack_name == "iam-ra-test-ca-cert-manager"

    def test_creates_first_scope_on_init_without_ca(
        self, aws_credentials, temp_xdg_dirs, initialized_state_no_ca: State
    ) -> None:
        """Should work even when state has init but no CAs yet."""
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            setup_state_in_aws(ctx, initialized_state_no_ca)

            mock_ca_result = SelfSignedCAResult(
                stack_name="iam-ra-test-ca-default",
                trust_anchor_arn=Arn(
                    "arn:aws:rolesanywhere:ap-southeast-2:123456789012:trust-anchor/ta-d"
                ),
                cert_s3_key="test/scopes/default/ca/certificate.pem",
                local_key_path=Path("/tmp/fake"),
            )

            with patch(
                "iam_ra_cli.workflows.ca.create_self_signed_ca",
                return_value=Ok(mock_ca_result),
            ):
                result = setup_ca(ctx, "test", scope="default")

            assert isinstance(result, Ok)
            assert result.value.trust_anchor_arn.resource_id == "ta-d"

    def test_passes_scope_to_operation(
        self, aws_credentials, temp_xdg_dirs, initialized_state: State
    ) -> None:
        """Should pass scope parameter to the CA operation."""
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            setup_state_in_aws(ctx, initialized_state)

            mock_ca_result = SelfSignedCAResult(
                stack_name="iam-ra-test-ca-longhorn-system",
                trust_anchor_arn=Arn(
                    "arn:aws:rolesanywhere:ap-southeast-2:123456789012:trust-anchor/ta-ls"
                ),
                cert_s3_key="test/scopes/longhorn-system/ca/certificate.pem",
                local_key_path=Path("/tmp/fake"),
            )

            with patch(
                "iam_ra_cli.workflows.ca.create_self_signed_ca",
                return_value=Ok(mock_ca_result),
            ) as mock_create:
                setup_ca(ctx, "test", scope="longhorn-system", validity_years=5)

            mock_create.assert_called_once()
            call_kwargs = mock_create.call_args
            assert call_kwargs.kwargs.get("scope") == "longhorn-system"
            assert call_kwargs.kwargs.get("validity_years") == 5

    def test_saves_state_after_creation(
        self, aws_credentials, temp_xdg_dirs, initialized_state: State
    ) -> None:
        """Should persist the new CA to state."""
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            setup_state_in_aws(ctx, initialized_state)

            mock_ca_result = SelfSignedCAResult(
                stack_name="iam-ra-test-ca-cert-manager",
                trust_anchor_arn=Arn(
                    "arn:aws:rolesanywhere:ap-southeast-2:123456789012:trust-anchor/ta-cm"
                ),
                cert_s3_key="test/scopes/cert-manager/ca/certificate.pem",
                local_key_path=Path("/tmp/fake"),
            )

            with patch(
                "iam_ra_cli.workflows.ca.create_self_signed_ca",
                return_value=Ok(mock_ca_result),
            ):
                setup_ca(ctx, "test", scope="cert-manager")

            # Verify by listing
            result = list_cas(ctx, "test")
            assert isinstance(result, Ok)
            assert "cert-manager" in result.value
            assert "default" in result.value


# =============================================================================
# delete_scope tests
# =============================================================================


class TestDeleteScope:
    """Tests for delete_scope workflow."""

    def test_fails_when_not_initialized(self, aws_credentials, temp_xdg_dirs) -> None:
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            result = delete_scope(ctx, "test", "default")
            assert isinstance(result, Err)
            assert isinstance(result.error, NotInitializedError)

    def test_fails_when_scope_not_found(
        self, aws_credentials, temp_xdg_dirs, initialized_state: State
    ) -> None:
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            setup_state_in_aws(ctx, initialized_state)

            result = delete_scope(ctx, "test", "nonexistent")
            assert isinstance(result, Err)
            assert isinstance(result.error, CAScopeNotFoundError)
            assert result.error.scope == "nonexistent"

    def test_deletes_scope(self, aws_credentials, temp_xdg_dirs, initialized_state: State) -> None:
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            setup_state_in_aws(ctx, initialized_state)

            with patch("iam_ra_cli.workflows.ca.delete_ca_op", return_value=Ok(None)):
                result = delete_scope(ctx, "test", "default")

            assert isinstance(result, Ok)

    def test_removes_scope_from_state(
        self, aws_credentials, temp_xdg_dirs, initialized_state: State
    ) -> None:
        """Deleting a scope should remove it from state."""
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            setup_state_in_aws(ctx, initialized_state)

            with patch("iam_ra_cli.workflows.ca.delete_ca_op", return_value=Ok(None)):
                delete_scope(ctx, "test", "default")

            result = list_cas(ctx, "test")
            assert isinstance(result, Ok)
            assert "default" not in result.value


# =============================================================================
# list_cas tests
# =============================================================================


class TestListCAs:
    """Tests for list_cas workflow."""

    def test_fails_when_not_initialized(self, aws_credentials, temp_xdg_dirs) -> None:
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            result = list_cas(ctx, "test")
            assert isinstance(result, Err)
            assert isinstance(result.error, NotInitializedError)

    def test_lists_empty(
        self, aws_credentials, temp_xdg_dirs, initialized_state_no_ca: State
    ) -> None:
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            setup_state_in_aws(ctx, initialized_state_no_ca)

            result = list_cas(ctx, "test")
            assert isinstance(result, Ok)
            assert result.value == {}

    def test_lists_all_scopes(
        self, aws_credentials, temp_xdg_dirs, initialized_state: State
    ) -> None:
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            # Add a second scope
            initialized_state.cas["cert-manager"] = CA(
                stack_name="iam-ra-test-ca-cert-manager",
                mode=CAMode.SELF_SIGNED,
                trust_anchor_arn=Arn(
                    "arn:aws:rolesanywhere:ap-southeast-2:123456789012:trust-anchor/ta-cm"
                ),
            )
            setup_state_in_aws(ctx, initialized_state)

            result = list_cas(ctx, "test")
            assert isinstance(result, Ok)
            assert len(result.value) == 2
            assert "default" in result.value
            assert "cert-manager" in result.value
