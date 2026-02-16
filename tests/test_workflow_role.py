"""Tests for workflows/role.py - Role management workflows.

These tests focus on validation logic and state management,
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
    CAScopeNotFoundError,
    NotInitializedError,
    RoleInUseError,
    RoleNotFoundError,
)
from iam_ra_cli.lib.result import Err, Ok
from iam_ra_cli.models import CA, Arn, CAMode, Host, Init, Role, State
from iam_ra_cli.operations.role import RoleResult
from iam_ra_cli.workflows.role import create_role, delete_role, list_roles


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
    """Create an initialized state with no roles."""
    return State(
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
                stack_name="iam-ra-test-rootca",
                mode=CAMode.SELF_SIGNED,
                trust_anchor_arn=Arn(
                    "arn:aws:rolesanywhere:ap-southeast-2:123456789012:trust-anchor/ta-123"
                ),
            ),
        },
    )


@pytest.fixture
def state_with_role(initialized_state: State) -> State:
    """Create state with an existing role."""
    initialized_state.roles["admin"] = Role(
        stack_name="iam-ra-test-role-admin",
        role_arn=Arn("arn:aws:iam::123456789012:role/iam-ra-test-admin"),
        profile_arn=Arn("arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/p-admin"),
        policies=(Arn("arn:aws:iam::aws:policy/AdministratorAccess"),),
    )
    return initialized_state


@pytest.fixture
def state_with_role_and_host(state_with_role: State) -> State:
    """Create state with a role that has a host using it."""
    state_with_role.hosts["web1"] = Host(
        stack_name="iam-ra-test-host-web1",
        hostname="web1",
        role_name="admin",
        certificate_secret_arn=Arn(
            "arn:aws:secretsmanager:ap-southeast-2:123456789012:secret:cert"
        ),
        private_key_secret_arn=Arn("arn:aws:secretsmanager:ap-southeast-2:123456789012:secret:key"),
    )
    return state_with_role


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


class TestCreateRole:
    """Tests for create_role workflow."""

    def test_create_role_fails_when_not_initialized(self, aws_credentials, temp_xdg_dirs) -> None:
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")

            result = create_role(ctx, "test", "admin")

            assert isinstance(result, Err)
            assert isinstance(result.error, NotInitializedError)
            assert result.error.namespace == "test"

    def test_create_role_is_idempotent_when_role_exists(
        self, aws_credentials, temp_xdg_dirs, state_with_role: State
    ) -> None:
        """Re-creating an existing role should update the CFN stack and succeed."""
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            setup_state_in_aws(ctx, state_with_role)

            mock_role_result = RoleResult(
                stack_name="iam-ra-test-role-admin",
                role_arn=Arn("arn:aws:iam::123456789012:role/iam-ra-test-admin"),
                profile_arn=Arn(
                    "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/p-admin"
                ),
                policies=(Arn("arn:aws:iam::aws:policy/AdministratorAccess"),),
            )

            with patch(
                "iam_ra_cli.workflows.role.create_role_op", return_value=Ok(mock_role_result)
            ):
                result = create_role(
                    ctx,
                    "test",
                    "admin",
                    policies=["arn:aws:iam::aws:policy/AdministratorAccess"],
                )

            assert isinstance(result, Ok)
            assert result.value.role_arn == Arn("arn:aws:iam::123456789012:role/iam-ra-test-admin")

    def test_create_role_updates_policies_when_role_exists(
        self, aws_credentials, temp_xdg_dirs, state_with_role: State
    ) -> None:
        """Re-creating an existing role with different policies should update state."""
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            setup_state_in_aws(ctx, state_with_role)

            new_policy = "arn:aws:iam::123456789012:policy/new-policy"
            mock_role_result = RoleResult(
                stack_name="iam-ra-test-role-admin",
                role_arn=Arn("arn:aws:iam::123456789012:role/iam-ra-test-admin"),
                profile_arn=Arn(
                    "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/p-admin"
                ),
                policies=(Arn(new_policy),),
            )

            with patch(
                "iam_ra_cli.workflows.role.create_role_op", return_value=Ok(mock_role_result)
            ):
                result = create_role(
                    ctx,
                    "test",
                    "admin",
                    policies=[new_policy],
                )

            assert isinstance(result, Ok)
            assert result.value.policies == (Arn(new_policy),)

    def test_create_role_succeeds(
        self, aws_credentials, temp_xdg_dirs, initialized_state: State
    ) -> None:
        """Test successful role creation by mocking the CFN operation."""
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            setup_state_in_aws(ctx, initialized_state)

            # Mock the role operation since moto can't handle our CFN template
            mock_role_result = RoleResult(
                stack_name="iam-ra-test-role-newrole",
                role_arn=Arn("arn:aws:iam::123456789012:role/iam-ra-test-newrole"),
                profile_arn=Arn("arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/p-new"),
                policies=(),
            )

            with patch(
                "iam_ra_cli.workflows.role.create_role_op", return_value=Ok(mock_role_result)
            ):
                result = create_role(ctx, "test", "newrole")

            assert isinstance(result, Ok)
            role = result.value
            assert role.stack_name == "iam-ra-test-role-newrole"

    def test_create_role_with_policies(
        self, aws_credentials, temp_xdg_dirs, initialized_state: State
    ) -> None:
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            setup_state_in_aws(ctx, initialized_state)

            policies = [
                "arn:aws:iam::aws:policy/ReadOnlyAccess",
                "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
            ]

            mock_role_result = RoleResult(
                stack_name="iam-ra-test-role-readonly",
                role_arn=Arn("arn:aws:iam::123456789012:role/iam-ra-test-readonly"),
                profile_arn=Arn("arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/p-ro"),
                policies=tuple(Arn(p) for p in policies),
            )

            with patch(
                "iam_ra_cli.workflows.role.create_role_op", return_value=Ok(mock_role_result)
            ):
                result = create_role(ctx, "test", "readonly", policies=policies)

            assert isinstance(result, Ok)
            assert len(result.value.policies) == 2


class TestDeleteRole:
    """Tests for delete_role workflow."""

    def test_delete_role_fails_when_not_initialized(self, aws_credentials, temp_xdg_dirs) -> None:
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")

            result = delete_role(ctx, "test", "admin")

            assert isinstance(result, Err)
            assert isinstance(result.error, NotInitializedError)

    def test_delete_role_fails_when_role_not_found(
        self, aws_credentials, temp_xdg_dirs, initialized_state: State
    ) -> None:
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            setup_state_in_aws(ctx, initialized_state)

            result = delete_role(ctx, "test", "nonexistent")

            assert isinstance(result, Err)
            assert isinstance(result.error, RoleNotFoundError)
            assert result.error.role_name == "nonexistent"

    def test_delete_role_fails_when_in_use(
        self, aws_credentials, temp_xdg_dirs, state_with_role_and_host: State
    ) -> None:
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            setup_state_in_aws(ctx, state_with_role_and_host)

            result = delete_role(ctx, "test", "admin")

            assert isinstance(result, Err)
            assert isinstance(result.error, RoleInUseError)
            assert result.error.role_name == "admin"
            assert "web1" in result.error.hosts

    def test_delete_role_with_force_ignores_usage(
        self, aws_credentials, temp_xdg_dirs, state_with_role_and_host: State
    ) -> None:
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            setup_state_in_aws(ctx, state_with_role_and_host)

            with patch("iam_ra_cli.workflows.role.delete_role_op", return_value=Ok(None)):
                result = delete_role(ctx, "test", "admin", force=True)

            assert isinstance(result, Ok)

    def test_delete_role_succeeds(
        self, aws_credentials, temp_xdg_dirs, state_with_role: State
    ) -> None:
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            setup_state_in_aws(ctx, state_with_role)

            with patch("iam_ra_cli.workflows.role.delete_role_op", return_value=Ok(None)):
                result = delete_role(ctx, "test", "admin")

            assert isinstance(result, Ok)


class TestListRoles:
    """Tests for list_roles workflow."""

    def test_list_roles_fails_when_not_initialized(self, aws_credentials, temp_xdg_dirs) -> None:
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")

            result = list_roles(ctx, "test")

            assert isinstance(result, Err)
            assert isinstance(result.error, NotInitializedError)

    def test_list_roles_empty(
        self, aws_credentials, temp_xdg_dirs, initialized_state: State
    ) -> None:
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            setup_state_in_aws(ctx, initialized_state)

            result = list_roles(ctx, "test")

            assert isinstance(result, Ok)
            assert result.value == {}

    def test_list_roles_with_roles(
        self, aws_credentials, temp_xdg_dirs, state_with_role: State
    ) -> None:
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            setup_state_in_aws(ctx, state_with_role)

            result = list_roles(ctx, "test")

            assert isinstance(result, Ok)
            assert "admin" in result.value
            assert result.value["admin"].stack_name == "iam-ra-test-role-admin"


class TestCreateRoleWithScope:
    """Tests for create_role workflow with --scope support."""

    def test_create_role_default_scope_uses_default_ca(
        self, aws_credentials, temp_xdg_dirs, initialized_state: State
    ) -> None:
        """When no scope given, role should use 'default' scope and its trust anchor."""
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            setup_state_in_aws(ctx, initialized_state)

            mock_role_result = RoleResult(
                stack_name="iam-ra-test-role-myrole",
                role_arn=Arn("arn:aws:iam::123456789012:role/iam-ra-test-myrole"),
                profile_arn=Arn(
                    "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/p-myrole"
                ),
                policies=(),
            )

            with patch(
                "iam_ra_cli.workflows.role.create_role_op", return_value=Ok(mock_role_result)
            ) as mock_op:
                result = create_role(ctx, "test", "myrole")

            assert isinstance(result, Ok)
            assert result.value.scope == "default"

            # Verify trust_anchor_arn was passed to the operation
            mock_op.assert_called_once()
            call_kwargs = mock_op.call_args
            assert call_kwargs.kwargs.get("trust_anchor_arn") == str(
                initialized_state.cas["default"].trust_anchor_arn
            ) or (
                len(call_kwargs.args) >= 4
                and str(initialized_state.cas["default"].trust_anchor_arn) in str(call_kwargs)
            )

    def test_create_role_explicit_scope_uses_scoped_ca(
        self, aws_credentials, temp_xdg_dirs
    ) -> None:
        """When --scope given, role should use that scope's trust anchor."""
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
        )

        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            setup_state_in_aws(ctx, state)

            mock_role_result = RoleResult(
                stack_name="iam-ra-test-role-cert-manager",
                role_arn=Arn("arn:aws:iam::123456789012:role/iam-ra-test-cert-manager"),
                profile_arn=Arn(
                    "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/p-certmgr"
                ),
                policies=(),
            )

            with patch(
                "iam_ra_cli.workflows.role.create_role_op", return_value=Ok(mock_role_result)
            ) as mock_op:
                result = create_role(ctx, "test", "cert-manager", scope="cert-manager")

            assert isinstance(result, Ok)
            assert result.value.scope == "cert-manager"

            # Verify the cert-manager trust anchor ARN was passed
            mock_op.assert_called_once()
            _, kwargs = mock_op.call_args
            assert kwargs["trust_anchor_arn"] == str(state.cas["cert-manager"].trust_anchor_arn)

    def test_create_role_fails_when_scope_not_found(
        self, aws_credentials, temp_xdg_dirs, initialized_state: State
    ) -> None:
        """Role creation fails if the requested scope doesn't have a CA set up."""
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            setup_state_in_aws(ctx, initialized_state)

            result = create_role(ctx, "test", "myrole", scope="nonexistent")

            assert isinstance(result, Err)
            assert isinstance(result.error, CAScopeNotFoundError)
            assert result.error.namespace == "test"
            assert result.error.scope == "nonexistent"

    def test_create_role_stores_scope_in_state(self, aws_credentials, temp_xdg_dirs) -> None:
        """The role saved to state should have the correct scope field."""
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
                "longhorn-system": CA(
                    stack_name="iam-ra-test-ca-longhorn-system",
                    mode=CAMode.SELF_SIGNED,
                    trust_anchor_arn=Arn(
                        "arn:aws:rolesanywhere:ap-southeast-2:123456789012:trust-anchor/ta-longhorn"
                    ),
                ),
            },
        )

        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            setup_state_in_aws(ctx, state)

            mock_role_result = RoleResult(
                stack_name="iam-ra-test-role-longhorn-backup",
                role_arn=Arn("arn:aws:iam::123456789012:role/iam-ra-test-longhorn-backup"),
                profile_arn=Arn(
                    "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/p-longhorn"
                ),
                policies=(Arn("arn:aws:iam::123456789012:policy/longhorn-backup"),),
            )

            with patch(
                "iam_ra_cli.workflows.role.create_role_op", return_value=Ok(mock_role_result)
            ):
                result = create_role(
                    ctx,
                    "test",
                    "longhorn-backup",
                    policies=["arn:aws:iam::123456789012:policy/longhorn-backup"],
                    scope="longhorn-system",
                )

            assert isinstance(result, Ok)
            role = result.value
            assert role.scope == "longhorn-system"
            assert role.stack_name == "iam-ra-test-role-longhorn-backup"
            assert len(role.policies) == 1

    def test_create_role_passes_trust_anchor_arn_to_operation(
        self, aws_credentials, temp_xdg_dirs, initialized_state: State
    ) -> None:
        """The trust_anchor_arn from the scope's CA must be forwarded to create_role_op."""
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            setup_state_in_aws(ctx, initialized_state)

            expected_ta_arn = str(initialized_state.cas["default"].trust_anchor_arn)

            mock_role_result = RoleResult(
                stack_name="iam-ra-test-role-testrole",
                role_arn=Arn("arn:aws:iam::123456789012:role/iam-ra-test-testrole"),
                profile_arn=Arn("arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/p-test"),
                policies=(),
            )

            with patch(
                "iam_ra_cli.workflows.role.create_role_op", return_value=Ok(mock_role_result)
            ) as mock_op:
                result = create_role(ctx, "test", "testrole")

            assert isinstance(result, Ok)
            mock_op.assert_called_once_with(
                ctx,
                "test",
                "testrole",
                None,
                3600,
                trust_anchor_arn=expected_ta_arn,
                scope="default",
            )

    def test_create_role_passes_scope_tag_to_operation(
        self, aws_credentials, temp_xdg_dirs
    ) -> None:
        """The scope should be passed to the operation for tagging."""
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
                "media": CA(
                    stack_name="iam-ra-test-ca-media",
                    mode=CAMode.SELF_SIGNED,
                    trust_anchor_arn=Arn(
                        "arn:aws:rolesanywhere:ap-southeast-2:123456789012:trust-anchor/ta-media"
                    ),
                ),
            },
        )

        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            setup_state_in_aws(ctx, state)

            mock_role_result = RoleResult(
                stack_name="iam-ra-test-role-downloader",
                role_arn=Arn("arn:aws:iam::123456789012:role/iam-ra-test-downloader"),
                profile_arn=Arn("arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/p-dl"),
                policies=(),
            )

            with patch(
                "iam_ra_cli.workflows.role.create_role_op", return_value=Ok(mock_role_result)
            ) as mock_op:
                result = create_role(ctx, "test", "downloader", scope="media")

            assert isinstance(result, Ok)
            _, kwargs = mock_op.call_args
            assert kwargs["scope"] == "media"
