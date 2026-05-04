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
    CannotRemoveLastRoleError,
    CAScopeNotFoundError,
    HostNotFoundError,
    NotInitializedError,
    RoleNotFoundError,
    RoleScopeMismatchError,
)
from iam_ra_cli.lib.result import Err, Ok
from iam_ra_cli.lib.sops import SopsProfile, SopsSecrets
from iam_ra_cli.models import CA, Arn, CAMode, Host, Init, NamespaceInfo, Role, State
from iam_ra_cli.operations.host import HostResult
from iam_ra_cli.operations.secrets import SecretsFileResult
from iam_ra_cli.workflows.host import (
    AddRoleConfig,
    OnboardConfig,
    RemoveRoleConfig,
    RotateCertConfig,
    add_role,
    onboard,
    remove_role,
    rotate_cert,
)


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
                    role_names=("admin",),
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
                    role_names=("cert-manager",),
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
                role_names=("longhorn-backup",),
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
                role_names=("nonexistent",),
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
                    role_names=("cert-manager",),
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
                    role_names=("admin",),
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
                role_names=("admin",),
                validity_days=365,
            )
            result = onboard(ctx, config)

            assert isinstance(result, Err)
            assert isinstance(result.error, NotInitializedError)


class TestOnboardResultFields:
    """OnboardResult must expose everything the CLI needs to guide the user's
    Nix setup: trust anchor / profile / role ARNs, region, namespace.

    Without these, the CLI only has secrets manager ARNs (internal AWS
    resources) and has to emit generic placeholder Nix snippets.
    """

    def test_result_has_trust_anchor_arn(
        self, aws_credentials, temp_xdg_dirs, state_default_scope: State
    ) -> None:
        """OnboardResult.trust_anchor_arn should match the scope's trust anchor."""
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
                    return_value=Ok(SecretsFileResult(path=Path("/tmp/s.yaml"), encrypted=False)),
                ),
            ):
                config = OnboardConfig(
                    namespace="test",
                    hostname="myhost",
                    role_names=("admin",),
                )
                result = onboard(ctx, config)

            assert isinstance(result, Ok)
            assert "ta-default" in str(result.value.trust_anchor_arn)

    def test_result_has_profile_and_role_arns(
        self, aws_credentials, temp_xdg_dirs, state_default_scope: State
    ) -> None:
        """OnboardResult.profile_arn/role_arn should match the role's."""
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
                    return_value=Ok(SecretsFileResult(path=Path("/tmp/s.yaml"), encrypted=False)),
                ),
            ):
                config = OnboardConfig(
                    namespace="test",
                    hostname="myhost",
                    role_names=("admin",),
                )
                result = onboard(ctx, config)

            assert isinstance(result, Ok)
            # v3: role_profiles replaces scalar profile_arn / role_arn
            assert len(result.value.role_profiles) == 1
            rp = result.value.role_profiles[0]
            assert rp.role_name == "admin"
            assert str(rp.profile_arn) == (
                "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/admin-profile"
            )
            assert str(rp.role_arn) == "arn:aws:iam::123456789012:role/admin"

    def test_result_has_region_and_namespace(
        self, aws_credentials, temp_xdg_dirs, state_default_scope: State
    ) -> None:
        """OnboardResult should carry region and namespace for downstream output."""
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
                    return_value=Ok(SecretsFileResult(path=Path("/tmp/s.yaml"), encrypted=False)),
                ),
            ):
                config = OnboardConfig(
                    namespace="test",
                    hostname="myhost",
                    role_names=("admin",),
                )
                result = onboard(ctx, config)

            assert isinstance(result, Ok)
            assert result.value.region == "ap-southeast-2"
            assert result.value.namespace == "test"

    def test_result_uses_per_scope_trust_anchor(
        self, aws_credentials, temp_xdg_dirs, state_multi_scope: State
    ) -> None:
        """With a scoped role, result.trust_anchor_arn must match that scope's TA."""
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
                    return_value=Ok(SecretsFileResult(path=Path("/tmp/s.yaml"), encrypted=False)),
                ),
            ):
                config = OnboardConfig(
                    namespace="test",
                    hostname="myhost",
                    role_names=("cert-manager",),
                )
                result = onboard(ctx, config)

            assert isinstance(result, Ok)
            assert "ta-certmgr" in str(result.value.trust_anchor_arn)
            assert "ta-default" not in str(result.value.trust_anchor_arn)


# =============================================================================
# add_role workflow (scenario 2: attach another role to an existing host
# without issuing a new cert)
# =============================================================================


def _state_with_existing_host(host_role_names: tuple[str, ...] = ("admin",)) -> State:
    """State with a host already onboarded with given roles.

    Includes two extra roles ready to be added: `readonly` (same scope,
    valid add) and `cross-scope` (different scope, invalid add).
    """
    return State(
        namespace="test",
        region="ap-southeast-2",
        version="2.5.0",
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
                stack_name="iam-ra-test-ca-default",
                mode=CAMode.SELF_SIGNED,
                trust_anchor_arn=Arn(
                    "arn:aws:rolesanywhere:ap-southeast-2:123456789012:trust-anchor/ta-default"
                ),
                account_id="123456789012",
            ),
            "other-scope": CA(
                stack_name="iam-ra-test-ca-other-scope",
                mode=CAMode.SELF_SIGNED,
                trust_anchor_arn=Arn(
                    "arn:aws:rolesanywhere:ap-southeast-2:123456789012:trust-anchor/ta-other"
                ),
                account_id="123456789012",
            ),
        },
        roles={
            "admin": Role(
                stack_name="iam-ra-test-role-admin",
                role_arn=Arn("arn:aws:iam::123456789012:role/admin"),
                profile_arn=Arn(
                    "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/admin"
                ),
                scope="default",
            ),
            "readonly": Role(
                stack_name="iam-ra-test-role-readonly",
                role_arn=Arn("arn:aws:iam::123456789012:role/readonly"),
                profile_arn=Arn(
                    "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/readonly"
                ),
                scope="default",
            ),
            "cross-scope": Role(
                stack_name="iam-ra-test-role-cross-scope",
                role_arn=Arn("arn:aws:iam::123456789012:role/cross-scope"),
                profile_arn=Arn(
                    "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/cross-scope"
                ),
                scope="other-scope",
            ),
        },
        hosts={
            "myhost": Host(
                stack_name="iam-ra-test-host-myhost",
                hostname="myhost",
                role_names=host_role_names,
                scope="default",
                certificate_secret_arn=Arn(
                    "arn:aws:secretsmanager:ap-southeast-2:123456789012:secret:cert"
                ),
                private_key_secret_arn=Arn(
                    "arn:aws:secretsmanager:ap-southeast-2:123456789012:secret:key"
                ),
            ),
        },
    )


def _setup_state_in_s3(ctx: AwsContext, state: State) -> None:
    """Helper: store state in mocked S3/SSM."""
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


def _mock_existing_sops(admin_only: bool = True) -> SopsSecrets:
    """A realistic SopsSecrets as would be read from the SOPS file on disk.

    Default is the single-role (admin) case that matches the host fixture.
    """
    profiles = [
        SopsProfile(
            role_name="admin",
            profile_arn="arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/admin",
            role_arn="arn:aws:iam::123456789012:role/admin",
        ),
    ]
    if not admin_only:
        profiles.append(
            SopsProfile(
                role_name="readonly",
                profile_arn=(
                    "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/readonly"
                ),
                role_arn="arn:aws:iam::123456789012:role/readonly",
            )
        )
    return SopsSecrets(
        certificate="CERT",
        private_key="KEY",
        trust_anchor_arn=(
            "arn:aws:rolesanywhere:ap-southeast-2:123456789012:trust-anchor/ta-default"
        ),
        account_id="123456789012",
        region="ap-southeast-2",
        profiles=tuple(profiles),
    )


class TestAddRoleSuccess:
    """add_role adds a role to an existing host without reissuing a cert."""

    def test_adds_role_to_state(self, aws_credentials, temp_xdg_dirs) -> None:
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            _setup_state_in_s3(ctx, _state_with_existing_host())

            with (
                patch(
                    "iam_ra_cli.workflows.host.decrypt_file",
                    return_value="<decrypted yaml>",
                ),
                patch(
                    "iam_ra_cli.workflows.host.parse_secrets_yaml",
                    return_value=_mock_existing_sops(),
                ),
                patch(
                    "iam_ra_cli.workflows.host.write_and_encrypt",
                    return_value=None,
                ),
            ):
                result = add_role(
                    ctx,
                    AddRoleConfig(
                        namespace="test",
                        hostname="myhost",
                        role_name="readonly",
                    ),
                )

            assert isinstance(result, Ok)
            assert set(result.value.updated_role_names) == {"admin", "readonly"}
            assert result.value.already_present is False

    def test_adds_role_to_sops_file(self, aws_credentials, temp_xdg_dirs) -> None:
        """The new profile must be appended to the SOPS file."""
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            _setup_state_in_s3(ctx, _state_with_existing_host())

            captured_yaml = {}

            def capture_write(content: str, path: Path, *a, **k) -> None:
                captured_yaml["content"] = content

            with (
                patch(
                    "iam_ra_cli.workflows.host.decrypt_file",
                    return_value="<decrypted yaml>",
                ),
                patch(
                    "iam_ra_cli.workflows.host.parse_secrets_yaml",
                    return_value=_mock_existing_sops(),
                ),
                patch(
                    "iam_ra_cli.workflows.host.write_and_encrypt",
                    side_effect=capture_write,
                ),
            ):
                result = add_role(
                    ctx,
                    AddRoleConfig(
                        namespace="test",
                        hostname="myhost",
                        role_name="readonly",
                    ),
                )

            assert isinstance(result, Ok)
            # The YAML content written back should mention both roles
            assert "admin" in captured_yaml["content"]
            assert "readonly" in captured_yaml["content"]
            # Specifically the new role's ARN
            assert "role/readonly" in captured_yaml["content"]

    def test_state_persists_new_role_list(
        self, aws_credentials, temp_xdg_dirs
    ) -> None:
        """After add_role, loading state should return the host with both roles."""
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            _setup_state_in_s3(ctx, _state_with_existing_host())

            with (
                patch("iam_ra_cli.workflows.host.decrypt_file", return_value="y"),
                patch(
                    "iam_ra_cli.workflows.host.parse_secrets_yaml",
                    return_value=_mock_existing_sops(),
                ),
                patch("iam_ra_cli.workflows.host.write_and_encrypt"),
            ):
                result = add_role(
                    ctx,
                    AddRoleConfig(
                        namespace="test", hostname="myhost", role_name="readonly"
                    ),
                )

            assert isinstance(result, Ok)

            # Verify the state persisted. We bypass cache to re-read from S3.
            from iam_ra_cli.lib import state as state_module

            loaded = state_module.load(ctx.ssm, ctx.s3, "test", skip_cache=True)
            assert isinstance(loaded, Ok) and loaded.value is not None
            assert set(loaded.value.hosts["myhost"].role_names) == {
                "admin",
                "readonly",
            }


class TestAddRoleIdempotent:
    """Re-running add_role with an already-attached role is a no-op (ok)."""

    def test_idempotent_returns_already_present(
        self, aws_credentials, temp_xdg_dirs
    ) -> None:
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            _setup_state_in_s3(ctx, _state_with_existing_host())

            with (
                patch("iam_ra_cli.workflows.host.decrypt_file", return_value="y"),
                patch(
                    "iam_ra_cli.workflows.host.parse_secrets_yaml",
                    return_value=_mock_existing_sops(),
                ),
                patch(
                    "iam_ra_cli.workflows.host.write_and_encrypt"
                ) as mock_write,
            ):
                result = add_role(
                    ctx,
                    AddRoleConfig(
                        namespace="test",
                        hostname="myhost",
                        role_name="admin",
                    ),
                )

            assert isinstance(result, Ok)
            assert result.value.already_present is True
            # No-op shouldn't rewrite the SOPS file
            mock_write.assert_not_called()


class TestAddRoleErrors:
    """Validation failures."""

    def test_host_not_found(self, aws_credentials, temp_xdg_dirs) -> None:
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            _setup_state_in_s3(ctx, _state_with_existing_host())

            result = add_role(
                ctx,
                AddRoleConfig(
                    namespace="test",
                    hostname="nonexistent-host",
                    role_name="admin",
                ),
            )

            assert isinstance(result, Err)
            assert isinstance(result.error, HostNotFoundError)

    def test_role_not_found(self, aws_credentials, temp_xdg_dirs) -> None:
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            _setup_state_in_s3(ctx, _state_with_existing_host())

            result = add_role(
                ctx,
                AddRoleConfig(
                    namespace="test",
                    hostname="myhost",
                    role_name="nonexistent-role",
                ),
            )

            assert isinstance(result, Err)
            assert isinstance(result.error, RoleNotFoundError)

    def test_scope_mismatch_rejected(
        self, aws_credentials, temp_xdg_dirs
    ) -> None:
        """Role and host in different scopes -> explicit rejection."""
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            _setup_state_in_s3(ctx, _state_with_existing_host())

            result = add_role(
                ctx,
                AddRoleConfig(
                    namespace="test",
                    hostname="myhost",
                    role_name="cross-scope",
                ),
            )

            assert isinstance(result, Err)
            assert isinstance(result.error, RoleScopeMismatchError)
            assert result.error.host_scope == "default"
            assert result.error.role_scope == "other-scope"

    def test_not_initialized(self, aws_credentials, temp_xdg_dirs) -> None:
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")

            result = add_role(
                ctx,
                AddRoleConfig(
                    namespace="fresh",
                    hostname="myhost",
                    role_name="admin",
                ),
            )

            assert isinstance(result, Err)
            assert isinstance(result.error, NotInitializedError)


# =============================================================================
# remove_role workflow
# =============================================================================


class TestRemoveRoleSuccess:
    def test_removes_role_from_state(
        self, aws_credentials, temp_xdg_dirs
    ) -> None:
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            _setup_state_in_s3(
                ctx,
                _state_with_existing_host(host_role_names=("admin", "readonly")),
            )

            with (
                patch("iam_ra_cli.workflows.host.decrypt_file", return_value="y"),
                patch(
                    "iam_ra_cli.workflows.host.parse_secrets_yaml",
                    return_value=_mock_existing_sops(admin_only=False),
                ),
                patch("iam_ra_cli.workflows.host.write_and_encrypt"),
            ):
                result = remove_role(
                    ctx,
                    RemoveRoleConfig(
                        namespace="test", hostname="myhost", role_name="readonly"
                    ),
                )

            assert isinstance(result, Ok)
            assert result.value.updated_role_names == ("admin",)
            assert result.value.already_absent is False

    def test_removes_from_sops_file(
        self, aws_credentials, temp_xdg_dirs
    ) -> None:
        """The profile should no longer appear in the rewritten SOPS."""
        captured: dict = {}

        def capture(content: str, path: Path, *a, **k) -> None:
            captured["content"] = content

        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            _setup_state_in_s3(
                ctx,
                _state_with_existing_host(host_role_names=("admin", "readonly")),
            )

            with (
                patch("iam_ra_cli.workflows.host.decrypt_file", return_value="y"),
                patch(
                    "iam_ra_cli.workflows.host.parse_secrets_yaml",
                    return_value=_mock_existing_sops(admin_only=False),
                ),
                patch(
                    "iam_ra_cli.workflows.host.write_and_encrypt",
                    side_effect=capture,
                ),
            ):
                remove_role(
                    ctx,
                    RemoveRoleConfig(
                        namespace="test", hostname="myhost", role_name="readonly"
                    ),
                )

            assert "role/readonly" not in captured["content"]
            assert "role/admin" in captured["content"]


class TestRemoveRoleIdempotent:
    def test_idempotent_returns_already_absent(
        self, aws_credentials, temp_xdg_dirs
    ) -> None:
        """Removing a role that isn't attached is a no-op (ok)."""
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            _setup_state_in_s3(ctx, _state_with_existing_host())

            with patch(
                "iam_ra_cli.workflows.host.write_and_encrypt"
            ) as mock_write:
                result = remove_role(
                    ctx,
                    RemoveRoleConfig(
                        namespace="test",
                        hostname="myhost",
                        role_name="readonly",
                    ),
                )

            assert isinstance(result, Ok)
            assert result.value.already_absent is True
            mock_write.assert_not_called()


class TestRemoveRoleErrors:
    def test_host_not_found(self, aws_credentials, temp_xdg_dirs) -> None:
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            _setup_state_in_s3(ctx, _state_with_existing_host())

            result = remove_role(
                ctx,
                RemoveRoleConfig(
                    namespace="test",
                    hostname="nope",
                    role_name="admin",
                ),
            )

            assert isinstance(result, Err)
            assert isinstance(result.error, HostNotFoundError)

    def test_cannot_remove_last_role(
        self, aws_credentials, temp_xdg_dirs
    ) -> None:
        """Removing the only role should fail with CannotRemoveLastRoleError.

        Leaving a host with zero roles is worse than leaving it with one;
        the user should offboard the host entirely instead.
        """
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            _setup_state_in_s3(
                ctx,
                _state_with_existing_host(host_role_names=("admin",)),
            )

            result = remove_role(
                ctx,
                RemoveRoleConfig(
                    namespace="test",
                    hostname="myhost",
                    role_name="admin",
                ),
            )

            assert isinstance(result, Err)
            assert isinstance(result.error, CannotRemoveLastRoleError)


# =============================================================================
# rotate_cert workflow (scenario 2 helper: renew cert, keep role list)
# =============================================================================


class TestRotateCertSuccess:
    """rotate_cert issues a new cert under the host's existing scope and
    updates Secrets Manager + SOPS in place, preserving role_names."""

    def test_rotates_self_signed_cert(
        self, aws_credentials, temp_xdg_dirs
    ) -> None:
        """Self-signed scope: new cert signed by the existing CA key on disk."""
        from iam_ra_cli.lib import crypto

        # Pre-create a CA on disk + in S3 matching the state fixture
        ca_kp = crypto.generate_ca(common_name="Test CA", validity_years=2)

        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            _setup_state_in_s3(
                ctx, _state_with_existing_host(host_role_names=("admin",))
            )

            # Put the CA cert into the state's bucket (scoped path)
            ctx.s3.put_object(
                Bucket="test-bucket",
                Key="test/scopes/default/ca/certificate.pem",
                Body=ca_kp.certificate.encode("utf-8"),
            )

            # Put the CA private key where operations/ca.py expects it
            from iam_ra_cli.lib import paths as paths_lib

            ca_key_path = (
                paths_lib.data_dir()
                / "test"
                / "scopes"
                / "default"
                / "ca-private-key.pem"
            )
            ca_key_path.parent.mkdir(parents=True, exist_ok=True)
            ca_key_path.write_text(ca_kp.private_key)

            # Pre-create the existing Secrets Manager secrets so rotate can
            # update them (arn-by-name is accepted by moto's put_secret_value).
            ctx.secrets.create_secret(
                Name=(
                    "arn:aws:secretsmanager:ap-southeast-2:"
                    "123456789012:secret:cert"
                ),
                SecretString="OLD-CERT",
            )
            ctx.secrets.create_secret(
                Name=(
                    "arn:aws:secretsmanager:ap-southeast-2:"
                    "123456789012:secret:key"
                ),
                SecretString="OLD-KEY",
            )

            with (
                patch(
                    "iam_ra_cli.workflows.host.decrypt_file",
                    return_value="decrypted yaml",
                ),
                patch(
                    "iam_ra_cli.workflows.host.parse_secrets_yaml",
                    return_value=_mock_existing_sops(),
                ),
                patch("iam_ra_cli.workflows.host.write_and_encrypt") as mock_write,
            ):
                result = rotate_cert(
                    ctx,
                    RotateCertConfig(
                        namespace="test",
                        hostname="myhost",
                        validity_days=90,
                    ),
                )

            assert isinstance(result, Ok)
            # SOPS file rewritten
            mock_write.assert_called_once()

    def test_preserves_role_names(
        self, aws_credentials, temp_xdg_dirs
    ) -> None:
        """role_names in state are unchanged after rotation."""
        from iam_ra_cli.lib import crypto

        ca_kp = crypto.generate_ca(common_name="Test CA")

        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            _setup_state_in_s3(
                ctx,
                _state_with_existing_host(host_role_names=("admin", "readonly")),
            )

            ctx.s3.put_object(
                Bucket="test-bucket",
                Key="test/scopes/default/ca/certificate.pem",
                Body=ca_kp.certificate.encode("utf-8"),
            )
            from iam_ra_cli.lib import paths as paths_lib

            ca_key_path = (
                paths_lib.data_dir()
                / "test"
                / "scopes"
                / "default"
                / "ca-private-key.pem"
            )
            ca_key_path.parent.mkdir(parents=True, exist_ok=True)
            ca_key_path.write_text(ca_kp.private_key)

            ctx.secrets.create_secret(
                Name=(
                    "arn:aws:secretsmanager:ap-southeast-2:"
                    "123456789012:secret:cert"
                ),
                SecretString="OLD-CERT",
            )
            ctx.secrets.create_secret(
                Name=(
                    "arn:aws:secretsmanager:ap-southeast-2:"
                    "123456789012:secret:key"
                ),
                SecretString="OLD-KEY",
            )

            with (
                patch(
                    "iam_ra_cli.workflows.host.decrypt_file", return_value="y"
                ),
                patch(
                    "iam_ra_cli.workflows.host.parse_secrets_yaml",
                    return_value=_mock_existing_sops(admin_only=False),
                ),
                patch("iam_ra_cli.workflows.host.write_and_encrypt"),
            ):
                result = rotate_cert(
                    ctx,
                    RotateCertConfig(
                        namespace="test", hostname="myhost", validity_days=365
                    ),
                )

            assert isinstance(result, Ok)

            # Reload state and verify role_names unchanged
            from iam_ra_cli.lib import state as state_module

            loaded = state_module.load(ctx.ssm, ctx.s3, "test", skip_cache=True)
            assert isinstance(loaded, Ok) and loaded.value is not None
            assert set(loaded.value.hosts["myhost"].role_names) == {
                "admin",
                "readonly",
            }

    def test_updates_secrets_manager(
        self, aws_credentials, temp_xdg_dirs
    ) -> None:
        """New cert/key land in Secrets Manager via put_secret_value."""
        from iam_ra_cli.lib import crypto

        ca_kp = crypto.generate_ca(common_name="Test CA")

        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            _setup_state_in_s3(ctx, _state_with_existing_host())

            ctx.s3.put_object(
                Bucket="test-bucket",
                Key="test/scopes/default/ca/certificate.pem",
                Body=ca_kp.certificate.encode("utf-8"),
            )
            from iam_ra_cli.lib import paths as paths_lib

            ca_key_path = (
                paths_lib.data_dir()
                / "test"
                / "scopes"
                / "default"
                / "ca-private-key.pem"
            )
            ca_key_path.parent.mkdir(parents=True, exist_ok=True)
            ca_key_path.write_text(ca_kp.private_key)

            ctx.secrets.create_secret(
                Name=(
                    "arn:aws:secretsmanager:ap-southeast-2:"
                    "123456789012:secret:cert"
                ),
                SecretString="OLD-CERT",
            )
            ctx.secrets.create_secret(
                Name=(
                    "arn:aws:secretsmanager:ap-southeast-2:"
                    "123456789012:secret:key"
                ),
                SecretString="OLD-KEY",
            )

            with (
                patch(
                    "iam_ra_cli.workflows.host.decrypt_file", return_value="y"
                ),
                patch(
                    "iam_ra_cli.workflows.host.parse_secrets_yaml",
                    return_value=_mock_existing_sops(),
                ),
                patch("iam_ra_cli.workflows.host.write_and_encrypt"),
            ):
                result = rotate_cert(
                    ctx,
                    RotateCertConfig(
                        namespace="test", hostname="myhost"
                    ),
                )

            assert isinstance(result, Ok)

            # Verify Secrets Manager received the new values
            cert = ctx.secrets.get_secret_value(
                SecretId="arn:aws:secretsmanager:ap-southeast-2:123456789012:secret:cert"
            )["SecretString"]
            key = ctx.secrets.get_secret_value(
                SecretId="arn:aws:secretsmanager:ap-southeast-2:123456789012:secret:key"
            )["SecretString"]
            assert cert != "OLD-CERT"
            assert key != "OLD-KEY"
            assert cert.startswith("-----BEGIN CERTIFICATE-----")
            assert key.startswith("-----BEGIN EC PRIVATE KEY-----")


class TestRotateCertErrors:
    def test_host_not_found(self, aws_credentials, temp_xdg_dirs) -> None:
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            _setup_state_in_s3(ctx, _state_with_existing_host())

            result = rotate_cert(
                ctx,
                RotateCertConfig(
                    namespace="test",
                    hostname="does-not-exist",
                ),
            )

            assert isinstance(result, Err)
            assert isinstance(result.error, HostNotFoundError)

    def test_not_initialized(self, aws_credentials, temp_xdg_dirs) -> None:
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")

            result = rotate_cert(
                ctx,
                RotateCertConfig(
                    namespace="fresh",
                    hostname="myhost",
                ),
            )

            assert isinstance(result, Err)
            assert isinstance(result.error, NotInitializedError)
