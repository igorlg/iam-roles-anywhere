"""Tests for the migrate_sops_paths workflow.

Scenario 3 wants every SOPS file to live at the namespace-suffixed path
(`secrets/hosts/<host>/iam-ra-<namespace>.yaml`). The previous PR added
canonical writes + a legacy-fallback reader; this workflow renames any
remaining legacy files in place.

Because renaming is a file-system operation (not an AWS call), these
tests build real directory trees in `tmp_path` rather than using moto.
"""

from pathlib import Path
from unittest.mock import patch

import pytest
from moto import mock_aws

from iam_ra_cli.lib.aws import AwsContext
from iam_ra_cli.lib.result import Err, Ok
from iam_ra_cli.models import CA, Arn, CAMode, Host, Init, NamespaceInfo, Role, State


@pytest.fixture
def aws_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "ap-southeast-2")


def _state_with_hosts(hostnames: tuple[str, ...]) -> State:
    """Minimal v3 state with the given hostnames."""
    return State(
        namespace="default",
        region="ap-southeast-2",
        version="3.0.0",
        namespace_info=NamespaceInfo(
            account_id="123456789012",
            region="ap-southeast-2",
        ),
        init=Init(
            stack_name="iam-ra-default-init",
            bucket_arn=Arn("arn:aws:s3:::test-bucket"),
            kms_key_arn=Arn(
                "arn:aws:kms:ap-southeast-2:123456789012:key/test-key"
            ),
        ),
        cas={
            "default": CA(
                stack_name="iam-ra-default-ca-default",
                mode=CAMode.SELF_SIGNED,
                trust_anchor_arn=Arn(
                    "arn:aws:rolesanywhere:ap-southeast-2:123456789012:trust-anchor/ta"
                ),
                account_id="123456789012",
            ),
        },
        roles={
            "admin": Role(
                stack_name="iam-ra-default-role-admin",
                role_arn=Arn("arn:aws:iam::123456789012:role/admin"),
                profile_arn=Arn(
                    "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/admin"
                ),
                scope="default",
            ),
        },
        hosts={
            h: Host(
                stack_name=f"iam-ra-default-host-{h}",
                hostname=h,
                role_names=("admin",),
                scope="default",
                certificate_secret_arn=Arn(
                    f"arn:aws:secretsmanager:ap-southeast-2:123:secret:{h}-cert"
                ),
                private_key_secret_arn=Arn(
                    f"arn:aws:secretsmanager:ap-southeast-2:123:secret:{h}-key"
                ),
            )
            for h in hostnames
        },
    )


def _setup_state_in_s3(ctx: AwsContext, state: State) -> None:
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


def _make_flake_with_hosts(
    tmp_path: Path, hostnames: tuple[str, ...], layout: dict[str, str]
) -> Path:
    """Create a fake Nix flake directory with the given hosts' SOPS files.

    ``layout[hostname]`` picks what to place:
        - "legacy": only `iam-ra.yaml`
        - "canonical": only `iam-ra-default.yaml`
        - "both":     both files
        - "none":     no SOPS file (host exists in state but the file is
                      missing from this machine)
    """
    flake = tmp_path / "nix-config"
    flake.mkdir()
    (flake / "flake.nix").write_text("{}")
    for h in hostnames:
        host_dir = flake / "secrets" / "hosts" / h
        host_dir.mkdir(parents=True)
        mode = layout.get(h, "legacy")
        if mode in ("legacy", "both"):
            (host_dir / "iam-ra.yaml").write_text(f"legacy sops file for {h}")
        if mode in ("canonical", "both"):
            (host_dir / "iam-ra-default.yaml").write_text(
                f"canonical sops file for {h}"
            )
    return flake


# =============================================================================
# migrate_sops_paths workflow
# =============================================================================


class TestMigrateSopsPathsNoop:
    """If no legacy files are found, the workflow is a success no-op."""

    def test_all_canonical_returns_empty(
        self, aws_credentials, tmp_path, monkeypatch
    ) -> None:
        from iam_ra_cli.workflows.migrate import migrate_sops_paths

        flake = _make_flake_with_hosts(
            tmp_path, ("h1", "h2"), {"h1": "canonical", "h2": "canonical"}
        )
        monkeypatch.chdir(flake)

        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            _setup_state_in_s3(ctx, _state_with_hosts(("h1", "h2")))

            result = migrate_sops_paths(ctx, "default")

        assert isinstance(result, Ok)
        assert result.value.renamed == ()
        assert result.value.would_rename == ()
        assert result.value.conflicts == ()

    def test_no_files_at_all_returns_empty(
        self, aws_credentials, tmp_path, monkeypatch
    ) -> None:
        """Hosts in state but no SOPS files on this machine - no-op, not an error."""
        from iam_ra_cli.workflows.migrate import migrate_sops_paths

        flake = _make_flake_with_hosts(tmp_path, ("h1",), {"h1": "none"})
        monkeypatch.chdir(flake)

        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            _setup_state_in_s3(ctx, _state_with_hosts(("h1",)))

            result = migrate_sops_paths(ctx, "default")

        assert isinstance(result, Ok)
        assert result.value.renamed == ()
        assert result.value.conflicts == ()


class TestMigrateSopsPathsApply:
    """When dry_run=False, legacy files are physically renamed."""

    def test_single_legacy_renamed(
        self, aws_credentials, tmp_path, monkeypatch
    ) -> None:
        from iam_ra_cli.workflows.migrate import migrate_sops_paths

        flake = _make_flake_with_hosts(tmp_path, ("h1",), {"h1": "legacy"})
        monkeypatch.chdir(flake)

        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            _setup_state_in_s3(ctx, _state_with_hosts(("h1",)))

            result = migrate_sops_paths(ctx, "default", dry_run=False)

        assert isinstance(result, Ok)
        assert result.value.renamed == ("h1",)

        host_dir = flake / "secrets" / "hosts" / "h1"
        assert not (host_dir / "iam-ra.yaml").exists()
        assert (host_dir / "iam-ra-default.yaml").exists()
        assert (host_dir / "iam-ra-default.yaml").read_text() == (
            "legacy sops file for h1"
        )

    def test_multiple_legacy_renamed(
        self, aws_credentials, tmp_path, monkeypatch
    ) -> None:
        from iam_ra_cli.workflows.migrate import migrate_sops_paths

        flake = _make_flake_with_hosts(
            tmp_path,
            ("h1", "h2", "h3"),
            {"h1": "legacy", "h2": "legacy", "h3": "canonical"},
        )
        monkeypatch.chdir(flake)

        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            _setup_state_in_s3(ctx, _state_with_hosts(("h1", "h2", "h3")))

            result = migrate_sops_paths(ctx, "default", dry_run=False)

        assert isinstance(result, Ok)
        assert set(result.value.renamed) == {"h1", "h2"}
        # h3 was already canonical -> not in renamed list
        assert "h3" not in result.value.renamed


class TestMigrateSopsPathsDryRun:
    """dry_run=True returns what WOULD be renamed without touching the FS."""

    def test_reports_without_renaming(
        self, aws_credentials, tmp_path, monkeypatch
    ) -> None:
        from iam_ra_cli.workflows.migrate import migrate_sops_paths

        flake = _make_flake_with_hosts(tmp_path, ("h1",), {"h1": "legacy"})
        monkeypatch.chdir(flake)

        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            _setup_state_in_s3(ctx, _state_with_hosts(("h1",)))

            result = migrate_sops_paths(ctx, "default", dry_run=True)

        assert isinstance(result, Ok)
        assert result.value.would_rename == ("h1",)
        assert result.value.renamed == ()

        # File system is untouched
        host_dir = flake / "secrets" / "hosts" / "h1"
        assert (host_dir / "iam-ra.yaml").exists()
        assert not (host_dir / "iam-ra-default.yaml").exists()


class TestMigrateSopsPathsConflicts:
    """When BOTH legacy and canonical exist for a host, abort with a clear
    error listing the hostnames - user resolves manually (the legacy and
    canonical files probably have different content; we can't guess which
    one to keep)."""

    def test_conflict_causes_error(
        self, aws_credentials, tmp_path, monkeypatch
    ) -> None:
        from iam_ra_cli.lib.errors import SopsPathConflictError
        from iam_ra_cli.workflows.migrate import migrate_sops_paths

        flake = _make_flake_with_hosts(tmp_path, ("h1",), {"h1": "both"})
        monkeypatch.chdir(flake)

        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            _setup_state_in_s3(ctx, _state_with_hosts(("h1",)))

            result = migrate_sops_paths(ctx, "default", dry_run=False)

        assert isinstance(result, Err)
        assert isinstance(result.error, SopsPathConflictError)
        assert "h1" in result.error.hostnames

        # Files must be untouched - we bailed early
        host_dir = flake / "secrets" / "hosts" / "h1"
        assert (host_dir / "iam-ra.yaml").exists()
        assert (host_dir / "iam-ra-default.yaml").exists()

    def test_conflict_in_dry_run_still_reports(
        self, aws_credentials, tmp_path, monkeypatch
    ) -> None:
        """Dry-run mode should still surface conflicts so the user can
        fix them before running with --apply."""
        from iam_ra_cli.lib.errors import SopsPathConflictError
        from iam_ra_cli.workflows.migrate import migrate_sops_paths

        flake = _make_flake_with_hosts(
            tmp_path,
            ("h1", "h2"),
            {"h1": "legacy", "h2": "both"},
        )
        monkeypatch.chdir(flake)

        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            _setup_state_in_s3(ctx, _state_with_hosts(("h1", "h2")))

            result = migrate_sops_paths(ctx, "default", dry_run=True)

        assert isinstance(result, Err)
        assert isinstance(result.error, SopsPathConflictError)
        assert "h2" in result.error.hostnames


class TestMigrateSopsPathsNonDefaultNamespace:
    """sops-paths migration only applies to the default namespace.

    Non-default namespaces never had a legacy filename - they were
    introduced with the suffix-by-default convention. Running
    migrate_sops_paths for a non-default namespace should be a no-op
    (there's nothing to find)."""

    def test_non_default_namespace_is_noop(
        self, aws_credentials, tmp_path, monkeypatch
    ) -> None:
        from iam_ra_cli.workflows.migrate import migrate_sops_paths

        flake = _make_flake_with_hosts(tmp_path, ("h1",), {"h1": "legacy"})
        monkeypatch.chdir(flake)

        # Set up state in namespace "work" (not "default")
        state = _state_with_hosts(("h1",))
        state.namespace = "work"

        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            _setup_state_in_s3(ctx, state)

            result = migrate_sops_paths(ctx, "work", dry_run=False)

        assert isinstance(result, Ok)
        # Legacy file is untouched - not in the "work" namespace scope
        assert (flake / "secrets" / "hosts" / "h1" / "iam-ra.yaml").exists()
        assert result.value.renamed == ()
