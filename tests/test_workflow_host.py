"""Tests for workflows/host.py - offboard, list, add/remove role.

Enrolment lives in tests/test_workflow_enrol.py. The v2 onboard and rotate_cert
workflows were removed in v3, along with their tests: onboard generated the host
key on the admin box, and rotate_cert rotated it from there, neither of which is
possible once the key never leaves the host.

The behaviour most worth protecting here is that offboarding a v4 host does NOT
try to delete a CloudFormation stack, because it has none.
"""

import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
from moto import mock_aws

from iam_ra_cli.lib.aws import AwsContext
from iam_ra_cli.lib.errors import (
    AccountMismatchError,
    CannotRemoveLastRoleError,
    HostNotFoundError,
    NotInitializedError,
    RoleNotFoundError,
    RoleScopeMismatchError,
)
from iam_ra_cli.lib.result import Err, Ok
from iam_ra_cli.models import CA, Arn, CAMode, Host, Init, NamespaceInfo, Role, State
from iam_ra_cli.workflows.host import (
    AddRoleConfig,
    RemoveRoleConfig,
    add_role,
    list_hosts,
    offboard,
    remove_role,
)

ACCOUNT = "123456789012"
BUCKET = "test-bucket"


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def aws_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "ap-southeast-2")


@pytest.fixture
def isolated_cache(monkeypatch: pytest.MonkeyPatch):
    with tempfile.TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)

        def cache_path(namespace: str) -> Path:
            return base / "cache" / namespace / "state.json"

        monkeypatch.setattr("iam_ra_cli.lib.state.paths.state_cache_path", cache_path)
        yield base


def _base_state() -> State:
    return State(
        namespace="test",
        region="ap-southeast-2",
        version="3.0.0-dev",
        namespace_info=NamespaceInfo(account_id=ACCOUNT, region="ap-southeast-2"),
        init=Init(
            stack_name="iam-ra-test-init",
            bucket_arn=Arn(f"arn:aws:s3:::{BUCKET}"),
            kms_key_arn=Arn(f"arn:aws:kms:ap-southeast-2:{ACCOUNT}:key/test-key"),
        ),
        cas={
            "default": CA(
                stack_name="iam-ra-test-ca-default",
                mode=CAMode.SELF_SIGNED,
                trust_anchor_arn=Arn(
                    f"arn:aws:rolesanywhere:ap-southeast-2:{ACCOUNT}:trust-anchor/ta-default"
                ),
            ),
            "other": CA(
                stack_name="iam-ra-test-ca-other",
                mode=CAMode.SELF_SIGNED,
                trust_anchor_arn=Arn(
                    f"arn:aws:rolesanywhere:ap-southeast-2:{ACCOUNT}:trust-anchor/ta-other"
                ),
            ),
        },
        roles={
            "admin": Role(
                stack_name="iam-ra-test-role-admin",
                role_arn=Arn(f"arn:aws:iam::{ACCOUNT}:role/admin"),
                profile_arn=Arn(
                    f"arn:aws:rolesanywhere:ap-southeast-2:{ACCOUNT}:profile/admin-p"
                ),
                scope="default",
            ),
            "readonly": Role(
                stack_name="iam-ra-test-role-readonly",
                role_arn=Arn(f"arn:aws:iam::{ACCOUNT}:role/readonly"),
                profile_arn=Arn(f"arn:aws:rolesanywhere:ap-southeast-2:{ACCOUNT}:profile/ro-p"),
                scope="default",
            ),
            "otherrole": Role(
                stack_name="iam-ra-test-role-other",
                role_arn=Arn(f"arn:aws:iam::{ACCOUNT}:role/other"),
                profile_arn=Arn(f"arn:aws:rolesanywhere:ap-southeast-2:{ACCOUNT}:profile/o-p"),
                scope="other",
            ),
        },
    )


V4_HOST = Host(
    hostname="v4host",
    role_names=("admin",),
    scope="default",
    key_store="files",
    certificate_serial="ABC123",
    not_after="2027-01-01T00:00:00+00:00",
)

LEGACY_HOST = Host(
    hostname="legacyhost",
    role_names=("admin",),
    scope="default",
    stack_name="iam-ra-test-host-legacyhost",
    certificate_secret_arn=Arn(
        f"arn:aws:secretsmanager:ap-southeast-2:{ACCOUNT}:secret:cert-1"
    ),
    private_key_secret_arn=Arn(f"arn:aws:secretsmanager:ap-southeast-2:{ACCOUNT}:secret:key-1"),
)


@pytest.fixture
def env(aws_credentials, isolated_cache):
    """Mocked AWS with a helper to (re)write the state document."""
    with mock_aws():
        ctx = AwsContext(region="ap-southeast-2", profile=None)
        ctx.s3.create_bucket(
            Bucket=BUCKET,
            CreateBucketConfiguration={"LocationConstraint": "ap-southeast-2"},
        )

        def put_state(state: State) -> None:
            ctx.s3.put_object(
                Bucket=BUCKET, Key="test/state.json", Body=state.to_json().encode()
            )
            ctx.ssm.put_parameter(
                Name="/iam-ra/test/state-location",
                Value=f"s3://{BUCKET}/test/state.json",
                Type="String",
                Overwrite=True,
            )

        put_state(_base_state())
        yield ctx, put_state


def _unwrap(result):  # noqa: ANN001, ANN202
    match result:
        case Ok(v):
            return v
        case Err(e):
            pytest.fail(f"expected Ok, got Err({e})")


def _reload(ctx: AwsContext) -> State:
    from iam_ra_cli.lib import state as state_module

    return _unwrap(state_module.load(ctx.ssm, ctx.s3, "test"))


# =============================================================================
# offboard
# =============================================================================


class TestOffboard:
    def test_v4_host_skips_cloudformation_teardown(self, env) -> None:
        """A v4 host has no stack and no S3 objects.

        Calling the teardown operation would pass stack_name=None to
        CloudFormation and fail, so it must be skipped entirely.
        """
        ctx, put_state = env
        state = _base_state()
        state.hosts["v4host"] = V4_HOST
        put_state(state)

        with patch("iam_ra_cli.workflows.host.offboard_host_op") as mock_op:
            _unwrap(offboard(ctx, "test", "v4host"))

        mock_op.assert_not_called()

    def test_v4_host_is_removed_from_state(self, env) -> None:
        ctx, put_state = env
        state = _base_state()
        state.hosts["v4host"] = V4_HOST
        put_state(state)

        _unwrap(offboard(ctx, "test", "v4host"))

        assert "v4host" not in _reload(ctx).hosts

    def test_legacy_host_does_tear_down_its_stack(self, env) -> None:
        """v2/v3 hosts still have AWS resources that must be removed."""
        ctx, put_state = env
        state = _base_state()
        state.hosts["legacyhost"] = LEGACY_HOST
        put_state(state)

        with patch("iam_ra_cli.workflows.host.offboard_host_op") as mock_op:
            mock_op.return_value = Ok(None)
            _unwrap(offboard(ctx, "test", "legacyhost"))

        mock_op.assert_called_once()
        args = mock_op.call_args[0]
        assert args[1] == "iam-ra-test-host-legacyhost"
        assert args[2] == BUCKET

    def test_legacy_host_is_removed_from_state(self, env) -> None:
        ctx, put_state = env
        state = _base_state()
        state.hosts["legacyhost"] = LEGACY_HOST
        put_state(state)

        with patch("iam_ra_cli.workflows.host.offboard_host_op") as mock_op:
            mock_op.return_value = Ok(None)
            _unwrap(offboard(ctx, "test", "legacyhost"))

        assert "legacyhost" not in _reload(ctx).hosts

    def test_unknown_host_fails(self, env) -> None:
        ctx, _put = env

        match offboard(ctx, "test", "nope"):
            case Err(e):
                assert isinstance(e, HostNotFoundError)
            case Ok(_):
                pytest.fail("unknown host should fail")

    def test_uninitialized_namespace_fails(self, aws_credentials, isolated_cache) -> None:
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2", profile=None)
            match offboard(ctx, "test", "v4host"):
                case Err(e):
                    assert isinstance(e, NotInitializedError)
                case Ok(_):
                    pytest.fail("uninitialized namespace should fail")

    def test_wrong_aws_account_fails(self, env) -> None:
        """The account pre-flight must fire before anything is deleted."""
        ctx, put_state = env
        state = _base_state()
        state.namespace_info = NamespaceInfo(account_id="999999999999", region="ap-southeast-2")
        state.hosts["v4host"] = V4_HOST
        put_state(state)

        match offboard(ctx, "test", "v4host"):
            case Err(e):
                assert isinstance(e, AccountMismatchError)
            case Ok(_):
                pytest.fail("account mismatch should fail")

        assert "v4host" in _reload(ctx).hosts


class TestListHosts:
    def test_lists_hosts(self, env) -> None:
        ctx, put_state = env
        state = _base_state()
        state.hosts["v4host"] = V4_HOST
        state.hosts["legacyhost"] = LEGACY_HOST
        put_state(state)

        hosts = _unwrap(list_hosts(ctx, "test"))

        assert set(hosts) == {"v4host", "legacyhost"}

    def test_empty(self, env) -> None:
        ctx, _put = env

        assert _unwrap(list_hosts(ctx, "test")) == {}

    def test_uninitialized_fails(self, aws_credentials, isolated_cache) -> None:
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2", profile=None)
            match list_hosts(ctx, "test"):
                case Err(e):
                    assert isinstance(e, NotInitializedError)
                case Ok(_):
                    pytest.fail("uninitialized namespace should fail")


# =============================================================================
# add_role / remove_role
# =============================================================================


class TestAddRole:
    def _setup(self, put_state, host: Host = V4_HOST) -> None:
        state = _base_state()
        state.hosts[host.hostname] = host
        put_state(state)

    def test_records_the_role(self, env) -> None:
        ctx, put_state = env
        self._setup(put_state)

        result = _unwrap(
            add_role(ctx, AddRoleConfig(namespace="test", hostname="v4host", role_name="readonly"))
        )

        assert result.already_present is False
        assert result.updated_role_names == ("admin", "readonly")
        assert _reload(ctx).hosts["v4host"].role_names == ("admin", "readonly")

    def test_returns_arns_for_the_nix_config(self, env) -> None:
        """Nothing writes the profile out for the user any more, so the ARNs
        they need must come back in the result."""
        ctx, put_state = env
        self._setup(put_state)

        result = _unwrap(
            add_role(ctx, AddRoleConfig(namespace="test", hostname="v4host", role_name="readonly"))
        )

        assert result.role_profile.role_name == "readonly"
        assert str(result.role_profile.profile_arn).endswith("profile/ro-p")
        assert str(result.role_profile.role_arn).endswith("role/readonly")

    def test_does_not_touch_the_certificate(self, env) -> None:
        """A certificate carries no role information, so adding a role must not
        reissue or invalidate it."""
        ctx, put_state = env
        self._setup(put_state)

        _unwrap(
            add_role(ctx, AddRoleConfig(namespace="test", hostname="v4host", role_name="readonly"))
        )

        host = _reload(ctx).hosts["v4host"]
        assert host.certificate_serial == V4_HOST.certificate_serial
        assert host.not_after == V4_HOST.not_after
        assert host.key_store == V4_HOST.key_store

    def test_idempotent(self, env) -> None:
        ctx, put_state = env
        self._setup(put_state)

        result = _unwrap(
            add_role(ctx, AddRoleConfig(namespace="test", hostname="v4host", role_name="admin"))
        )

        assert result.already_present is True
        assert result.updated_role_names == ("admin",)

    def test_unknown_role_fails(self, env) -> None:
        ctx, put_state = env
        self._setup(put_state)

        match add_role(
            ctx, AddRoleConfig(namespace="test", hostname="v4host", role_name="nope")
        ):
            case Err(e):
                assert isinstance(e, RoleNotFoundError)
            case Ok(_):
                pytest.fail("unknown role should fail")

    def test_unknown_host_fails(self, env) -> None:
        ctx, _put = env

        match add_role(ctx, AddRoleConfig(namespace="test", hostname="nope", role_name="admin")):
            case Err(e):
                assert isinstance(e, HostNotFoundError)
            case Ok(_):
                pytest.fail("unknown host should fail")

    def test_cross_scope_role_fails(self, env) -> None:
        """A host's cert authenticates against one trust anchor, so a role from
        another scope is unusable with it."""
        ctx, put_state = env
        self._setup(put_state)

        match add_role(
            ctx, AddRoleConfig(namespace="test", hostname="v4host", role_name="otherrole")
        ):
            case Err(e):
                assert isinstance(e, RoleScopeMismatchError)
                assert e.host_scope == "default"
                assert e.role_scope == "other"
            case Ok(_):
                pytest.fail("cross-scope role should fail")

    def test_works_for_a_legacy_host_too(self, env) -> None:
        ctx, put_state = env
        self._setup(put_state, LEGACY_HOST)

        result = _unwrap(
            add_role(
                ctx, AddRoleConfig(namespace="test", hostname="legacyhost", role_name="readonly")
            )
        )

        assert result.updated_role_names == ("admin", "readonly")


class TestRemoveRole:
    def _setup(self, put_state, role_names: tuple[str, ...]) -> None:
        state = _base_state()
        state.hosts["v4host"] = Host(
            hostname="v4host", role_names=role_names, scope="default", key_store="files"
        )
        put_state(state)

    def test_removes_the_role(self, env) -> None:
        ctx, put_state = env
        self._setup(put_state, ("admin", "readonly"))

        result = _unwrap(
            remove_role(
                ctx, RemoveRoleConfig(namespace="test", hostname="v4host", role_name="readonly")
            )
        )

        assert result.already_absent is False
        assert result.updated_role_names == ("admin",)
        assert _reload(ctx).hosts["v4host"].role_names == ("admin",)

    def test_idempotent(self, env) -> None:
        ctx, put_state = env
        self._setup(put_state, ("admin",))

        result = _unwrap(
            remove_role(
                ctx, RemoveRoleConfig(namespace="test", hostname="v4host", role_name="readonly")
            )
        )

        assert result.already_absent is True
        assert result.updated_role_names == ("admin",)

    def test_refuses_to_remove_the_last_role(self, env) -> None:
        """A host with no roles has a certificate but nothing to assume."""
        ctx, put_state = env
        self._setup(put_state, ("admin",))

        match remove_role(
            ctx, RemoveRoleConfig(namespace="test", hostname="v4host", role_name="admin")
        ):
            case Err(e):
                assert isinstance(e, CannotRemoveLastRoleError)
            case Ok(_):
                pytest.fail("removing the last role should fail")

        assert _reload(ctx).hosts["v4host"].role_names == ("admin",)

    def test_unknown_host_fails(self, env) -> None:
        ctx, _put = env

        match remove_role(
            ctx, RemoveRoleConfig(namespace="test", hostname="nope", role_name="admin")
        ):
            case Err(e):
                assert isinstance(e, HostNotFoundError)
            case Ok(_):
                pytest.fail("unknown host should fail")
