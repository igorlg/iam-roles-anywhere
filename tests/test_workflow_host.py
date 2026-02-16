"""Tests for workflows/host.py - Host onboard/offboard with scoped CAs.

Phase 5: host workflow derives scope from role, uses scoped CA cert/key
and scoped trust anchor ARN for SOPS secrets file.

These tests mock the operations layer (CFN deployment + secrets) since
moto has limited support for the complex CloudFormation templates.
"""

import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
from moto import mock_aws

from iam_ra_cli.lib.aws import AwsContext
from iam_ra_cli.lib.errors import (
    CAScopeNotFoundError,
    NotInitializedError,
    RoleNotFoundError,
)
from iam_ra_cli.lib.result import Err, Ok
from iam_ra_cli.models import CA, Arn, CAMode, Host, Init, Role, State
from iam_ra_cli.operations.host import HostResult
from iam_ra_cli.operations.secrets import SecretsFileResult
from iam_ra_cli.workflows.host import OnboardConfig, onboard


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


@pytest.fixture
def state_default_scope() -> State:
    """State with a role in the default scope."""
    state = State(
        namespace="test",
        region="ap-southeast-2",
        version="0.1.0",
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
        roles={
            "admin": Role(
                stack_name="iam-ra-test-role-admin",
                role_arn=Arn("arn:aws:iam::123456789012:role/admin"),
                profile_arn=Arn(
                    "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/admin-profile"
                ),
                scope="default",
            ),
        },
    )
    return state


@pytest.fixture
def state_multi_scope() -> State:
    """State with roles in multiple scopes."""
    state = State(
        namespace="test",
        region="ap-southeast-2",
        version="0.1.0",
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
            "cert-manager": CA(
                stack_name="iam-ra-test-ca-cert-manager",
                mode=CAMode.SELF_SIGNED,
                trust_anchor_arn=Arn(
                    "arn:aws:rolesanywhere:ap-southeast-2:123456789012:trust-anchor/ta-certmgr"
                ),
            ),
        },
        roles={
            "admin": Role(
                stack_name="iam-ra-test-role-admin",
                role_arn=Arn("arn:aws:iam::123456789012:role/admin"),
                profile_arn=Arn(
                    "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/admin-profile"
                ),
                scope="default",
            ),
            "cert-manager": Role(
                stack_name="iam-ra-test-role-cert-manager",
                role_arn=Arn("arn:aws:iam::123456789012:role/cert-manager"),
                profile_arn=Arn(
                    "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/certmgr-profile"
                ),
                scope="cert-manager",
            ),
        },
    )
    return state


@pytest.fixture
def state_missing_scope() -> State:
    """State with a role whose scope has no CA."""
    state = State(
        namespace="test",
        region="ap-southeast-2",
        version="0.1.0",
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
            # No "longhorn-system" CA
        },
        roles={
            "longhorn-backup": Role(
                stack_name="iam-ra-test-role-longhorn-backup",
                role_arn=Arn("arn:aws:iam::123456789012:role/longhorn-backup"),
                profile_arn=Arn(
                    "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/longhorn-profile"
                ),
                scope="longhorn-system",
            ),
        },
    )
    return state


MOCK_HOST_RESULT = HostResult(
    stack_name="iam-ra-test-host-myhost",
    hostname="myhost",
    certificate_secret_arn=Arn(
        "arn:aws:secretsmanager:ap-southeast-2:123456789012:secret:cert-abc"
    ),
    private_key_secret_arn=Arn("arn:aws:secretsmanager:ap-southeast-2:123456789012:secret:key-xyz"),
)


# =============================================================================
# Tests: Scope Derivation
# =============================================================================


class TestOnboardScopeDerivation:
    """Host onboard should derive scope from the role and use its CA."""

    def test_default_scope_uses_default_trust_anchor_for_sops(
        self, aws_credentials, temp_xdg_dirs, state_default_scope: State
    ) -> None:
        """Onboard with default-scope role should pass default trust anchor to SOPS."""
        captured_ta_arn = {}

        def fake_create_secrets(ctx, **kwargs):
            captured_ta_arn["value"] = kwargs["trust_anchor_arn"]
            return Ok(SecretsFileResult(path=Path("/tmp/secrets.yaml"), encrypted=False))

        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            setup_state_in_aws(ctx, state_default_scope)

            with (
                patch(
                    "iam_ra_cli.workflows.host.onboard_host_self_signed",
                    return_value=Ok(MOCK_HOST_RESULT),
                ),
                patch(
                    "iam_ra_cli.workflows.host.create_secrets_file",
                    side_effect=fake_create_secrets,
                ),
            ):
                config = OnboardConfig(
                    namespace="test",
                    hostname="myhost",
                    role_name="admin",
                    validity_days=365,
                    create_sops=True,
                )
                result = onboard(ctx, config)

            assert isinstance(result, Ok)
            assert "ta-default" in captured_ta_arn["value"]

    def test_nondefault_scope_uses_scoped_trust_anchor_for_sops(
        self, aws_credentials, temp_xdg_dirs, state_multi_scope: State
    ) -> None:
        """Onboard with cert-manager-scope role should pass cert-manager trust anchor to SOPS."""
        captured_ta_arn = {}

        def fake_create_secrets(ctx, **kwargs):
            captured_ta_arn["value"] = kwargs["trust_anchor_arn"]
            return Ok(SecretsFileResult(path=Path("/tmp/secrets.yaml"), encrypted=False))

        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            setup_state_in_aws(ctx, state_multi_scope)

            with (
                patch(
                    "iam_ra_cli.workflows.host.onboard_host_self_signed",
                    return_value=Ok(MOCK_HOST_RESULT),
                ),
                patch(
                    "iam_ra_cli.workflows.host.create_secrets_file",
                    side_effect=fake_create_secrets,
                ),
            ):
                config = OnboardConfig(
                    namespace="test",
                    hostname="myhost",
                    role_name="cert-manager",
                    validity_days=365,
                    create_sops=True,
                )
                result = onboard(ctx, config)

            assert isinstance(result, Ok)
            assert "ta-certmgr" in captured_ta_arn["value"]
            assert "ta-default" not in captured_ta_arn["value"]

    def test_scope_not_found_returns_error(
        self, aws_credentials, temp_xdg_dirs, state_missing_scope: State
    ) -> None:
        """Onboard should fail if the role's scope has no CA."""
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            setup_state_in_aws(ctx, state_missing_scope)

            config = OnboardConfig(
                namespace="test",
                hostname="myhost",
                role_name="longhorn-backup",
                validity_days=365,
            )
            result = onboard(ctx, config)

            assert isinstance(result, Err)
            assert isinstance(result.error, CAScopeNotFoundError)
            assert result.error.scope == "longhorn-system"

    def test_role_not_found_still_fails(
        self, aws_credentials, temp_xdg_dirs, state_default_scope: State
    ) -> None:
        """Onboard should fail if role doesn't exist (unchanged behavior)."""
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            setup_state_in_aws(ctx, state_default_scope)

            config = OnboardConfig(
                namespace="test",
                hostname="myhost",
                role_name="nonexistent",
                validity_days=365,
            )
            result = onboard(ctx, config)

            assert isinstance(result, Err)
            assert isinstance(result.error, RoleNotFoundError)


class TestOnboardOperationsReceiveScope:
    """Host onboard should pass scope-derived CA paths to operations."""

    def test_self_signed_operation_called_with_scope_param(
        self, aws_credentials, temp_xdg_dirs, state_multi_scope: State
    ) -> None:
        """The operations layer should receive the scope so it reads the correct CA."""
        captured_kwargs = {}

        def fake_onboard_self_signed(
            ctx, namespace, hostname, bucket_name, validity_days, scope="default"
        ):
            captured_kwargs.update(
                namespace=namespace,
                hostname=hostname,
                bucket_name=bucket_name,
                validity_days=validity_days,
                scope=scope,
            )
            return Ok(MOCK_HOST_RESULT)

        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            setup_state_in_aws(ctx, state_multi_scope)

            with (
                patch(
                    "iam_ra_cli.workflows.host.onboard_host_self_signed",
                    side_effect=fake_onboard_self_signed,
                ),
                patch(
                    "iam_ra_cli.workflows.host.create_secrets_file",
                    return_value=Ok(SecretsFileResult(path=Path("/tmp/s.yaml"), encrypted=False)),
                ),
            ):
                config = OnboardConfig(
                    namespace="test",
                    hostname="myhost",
                    role_name="cert-manager",
                    validity_days=90,
                    create_sops=True,
                )
                result = onboard(ctx, config)

            assert isinstance(result, Ok)
            assert captured_kwargs["scope"] == "cert-manager"
            assert captured_kwargs["validity_days"] == 90

    def test_default_scope_passes_default_to_operation(
        self, aws_credentials, temp_xdg_dirs, state_default_scope: State
    ) -> None:
        """Default-scope role should pass scope='default' to operations."""
        captured_kwargs = {}

        def fake_onboard_self_signed(
            ctx, namespace, hostname, bucket_name, validity_days, scope="default"
        ):
            captured_kwargs["scope"] = scope
            return Ok(MOCK_HOST_RESULT)

        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            setup_state_in_aws(ctx, state_default_scope)

            with (
                patch(
                    "iam_ra_cli.workflows.host.onboard_host_self_signed",
                    side_effect=fake_onboard_self_signed,
                ),
                patch(
                    "iam_ra_cli.workflows.host.create_secrets_file",
                    return_value=Ok(SecretsFileResult(path=Path("/tmp/s.yaml"), encrypted=False)),
                ),
            ):
                config = OnboardConfig(
                    namespace="test",
                    hostname="myhost",
                    role_name="admin",
                    validity_days=365,
                    create_sops=True,
                )
                result = onboard(ctx, config)

            assert isinstance(result, Ok)
            assert captured_kwargs["scope"] == "default"


class TestOnboardErrorTypeUnion:
    """OnboardError type should include CAScopeNotFoundError."""

    def test_not_initialized_still_fails(self, aws_credentials, temp_xdg_dirs) -> None:
        """Onboard should still fail when not initialized."""
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")

            config = OnboardConfig(
                namespace="nonexistent",
                hostname="myhost",
                role_name="admin",
                validity_days=365,
            )
            result = onboard(ctx, config)

            assert isinstance(result, Err)
            assert isinstance(result.error, NotInitializedError)
