"""Tests for commands/host.py - onboard output rendering.

These cover the split between the ARN identifiers users need in Nix
config vs the internal Secrets Manager ARNs, plus the relative-path
logic for SOPS files inside vs outside a Nix flake repo.
"""

from pathlib import Path
from unittest.mock import patch

from iam_ra_cli.commands.host import (
    _render_nix_snippet,
    _sops_paths,
)
from iam_ra_cli.models import Arn, Host
from iam_ra_cli.operations.secrets import SecretsFileResult
from iam_ra_cli.workflows.host import OnboardResult

# =============================================================================
# Fixtures (module-level helpers, not pytest fixtures)
# =============================================================================


def _make_onboard_result(secrets_file: SecretsFileResult | None = None) -> OnboardResult:
    """Build a realistic OnboardResult for tests."""
    host = Host(
        stack_name="iam-ra-default-host-myhost",
        hostname="myhost",
        role_name="iamra-admin",
        certificate_secret_arn=Arn(
            "arn:aws:secretsmanager:ap-southeast-2:123456789012:secret:iam-ra/default/myhost/certificate-abc123"
        ),
        private_key_secret_arn=Arn(
            "arn:aws:secretsmanager:ap-southeast-2:123456789012:secret:iam-ra/default/myhost/private-key-xyz789"
        ),
    )
    return OnboardResult(
        host=host,
        secrets_file=secrets_file,
        namespace="default",
        region="ap-southeast-2",
        trust_anchor_arn=Arn(
            "arn:aws:rolesanywhere:ap-southeast-2:123456789012:trust-anchor/ta-1"
        ),
        profile_arn=Arn(
            "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/profile-1"
        ),
        role_arn=Arn(
            "arn:aws:iam::123456789012:role/iam-ra-default-iamra-admin"
        ),
    )


# =============================================================================
# _sops_paths
# =============================================================================


class TestSopsPaths:
    """Path resolution for SOPS file (absolute + relative-to-flake)."""

    def test_file_inside_flake_repo_returns_relative(self, tmp_path: Path) -> None:
        """When the SOPS file is under a flake.nix dir, relative path is returned."""
        flake_root = tmp_path / "my-nix-config"
        flake_root.mkdir()
        (flake_root / "flake.nix").write_text("{}")
        sops_file = flake_root / "secrets" / "hosts" / "myhost" / "iam-ra.yaml"
        sops_file.parent.mkdir(parents=True)
        sops_file.write_text("...")

        with patch(
            "iam_ra_cli.commands.host.get_nix_repo_root", return_value=flake_root
        ):
            absolute, repo_root, relative = _sops_paths(sops_file)

        assert absolute == sops_file.resolve()
        assert repo_root == flake_root
        assert relative == Path("secrets/hosts/myhost/iam-ra.yaml")

    def test_file_outside_flake_returns_none_relative(self, tmp_path: Path) -> None:
        """When SOPS file is outside the flake (e.g. /tmp), relative is None."""
        flake_root = tmp_path / "nix-config"
        flake_root.mkdir()
        (flake_root / "flake.nix").write_text("{}")
        sops_file = tmp_path / "elsewhere" / "iam-ra.yaml"
        sops_file.parent.mkdir()
        sops_file.write_text("...")

        with patch(
            "iam_ra_cli.commands.host.get_nix_repo_root", return_value=flake_root
        ):
            absolute, repo_root, relative = _sops_paths(sops_file)

        assert absolute == sops_file.resolve()
        assert repo_root == flake_root
        assert relative is None

    def test_no_flake_found_returns_none_relative(self, tmp_path: Path) -> None:
        """Without a flake.nix anywhere, relative is None."""
        sops_file = tmp_path / "iam-ra.yaml"
        sops_file.write_text("...")

        with patch("iam_ra_cli.commands.host.get_nix_repo_root", return_value=None):
            absolute, repo_root, relative = _sops_paths(sops_file)

        assert absolute == sops_file.resolve()
        assert repo_root is None
        assert relative is None


# =============================================================================
# _render_nix_snippet
# =============================================================================


class TestRenderNixSnippet:
    """Nix snippet must use real ARN values (not placeholders)."""

    def test_snippet_contains_real_trust_anchor_arn(self) -> None:
        result = _make_onboard_result()
        lines = _render_nix_snippet(result, rel_sops_path=None)
        rendered = "\n".join(lines)
        assert str(result.trust_anchor_arn) in rendered

    def test_snippet_contains_real_profile_and_role_arns(self) -> None:
        result = _make_onboard_result()
        lines = _render_nix_snippet(result, rel_sops_path=None)
        rendered = "\n".join(lines)
        assert str(result.profile_arn) in rendered
        assert str(result.role_arn) in rendered

    def test_snippet_contains_region(self) -> None:
        result = _make_onboard_result()
        lines = _render_nix_snippet(result, rel_sops_path=None)
        rendered = "\n".join(lines)
        assert 'region = "ap-southeast-2"' in rendered

    def test_snippet_uses_role_name_as_profile_key(self) -> None:
        """The profiles.<key> in the snippet should match the role name."""
        result = _make_onboard_result()
        lines = _render_nix_snippet(result, rel_sops_path=None)
        rendered = "\n".join(lines)
        assert "profiles.iamra-admin" in rendered

    def test_snippet_uses_real_sops_path_when_provided(self) -> None:
        result = _make_onboard_result()
        rel = Path("secrets/hosts/myhost/iam-ra.yaml")
        lines = _render_nix_snippet(result, rel_sops_path=rel)
        rendered = "\n".join(lines)
        # Nix path literal form: ./secrets/hosts/...
        assert "./secrets/hosts/myhost/iam-ra.yaml" in rendered
        assert "/path/to/iam-ra.yaml" not in rendered

    def test_snippet_uses_placeholder_when_no_rel_path(self) -> None:
        """No relative path available -> fall back to placeholder the user edits."""
        result = _make_onboard_result()
        lines = _render_nix_snippet(result, rel_sops_path=None)
        rendered = "\n".join(lines)
        assert "./path/to/iam-ra.yaml" in rendered

    def test_snippet_uses_documented_module_api(self) -> None:
        """The snippet must use programs.iamRolesAnywhere (the public API)."""
        result = _make_onboard_result()
        lines = _render_nix_snippet(result, rel_sops_path=None)
        rendered = "\n".join(lines)
        assert "programs.iamRolesAnywhere" in rendered
        assert "certificate = {" in rendered
        assert "certPath" in rendered
        assert "keyPath" in rendered

    def test_verification_command_uses_role_name(self) -> None:
        """The verify step should reference the actual profile the user just created."""
        result = _make_onboard_result()
        lines = _render_nix_snippet(result, rel_sops_path=None)
        rendered = "\n".join(lines)
        assert "aws sts get-caller-identity --profile iamra-admin" in rendered


# =============================================================================
# End-to-end: _render_human via captured stdout
# =============================================================================


class TestRenderHumanOutput:
    """Full human-readable output should prioritise Nix-facing ARNs and
    de-emphasize Secrets Manager ARNs.
    """

    def _render(self, result: OnboardResult) -> str:
        """Invoke _render_human and capture its click.echo output."""
        from iam_ra_cli.commands.host import _render_human

        captured: list[str] = []

        def fake_echo(message: str | None = None, *args, **kwargs) -> None:
            captured.append("" if message is None else message)

        def fake_secho(message: str | None = None, *args, **kwargs) -> None:
            captured.append("" if message is None else message)

        with (
            patch("iam_ra_cli.commands.host.click.echo", side_effect=fake_echo),
            patch("iam_ra_cli.commands.host.click.secho", side_effect=fake_secho),
        ):
            _render_human(result)

        return "\n".join(captured)

    def test_includes_hostname_namespace_region_role(self) -> None:
        result = _make_onboard_result()
        out = self._render(result)
        assert "myhost" in out
        assert "default" in out
        assert "ap-southeast-2" in out
        assert "iamra-admin" in out

    def test_includes_trust_anchor_profile_role_arns(self) -> None:
        result = _make_onboard_result()
        out = self._render(result)
        assert str(result.trust_anchor_arn) in out
        assert str(result.profile_arn) in out
        assert str(result.role_arn) in out

    def test_secrets_manager_arns_appear_after_identifiers(self) -> None:
        """Internal Secrets Manager ARNs should come AFTER the Nix identifiers,
        not before. This enforces the de-emphasis ordering.
        """
        result = _make_onboard_result()
        out = self._render(result)

        ta_pos = out.index(str(result.trust_anchor_arn))
        sm_cert_pos = out.index(str(result.host.certificate_secret_arn))

        assert ta_pos < sm_cert_pos, (
            "Trust Anchor ARN must appear before the Secrets Manager ARN "
            "in the output; users need the former for Nix config."
        )

    def test_no_sops_mode_skips_nix_snippet(self) -> None:
        """With --no-sops, don't emit the full Nix snippet (no SOPS file to ref)."""
        result = _make_onboard_result(secrets_file=None)
        out = self._render(result)
        # Still shows the identifiers
        assert str(result.trust_anchor_arn) in out
        # But no sops.secrets block
        assert "sops.secrets" not in out

    def test_sops_keys_listed(self) -> None:
        """The output should tell the user what keys are in the SOPS file."""
        sops = SecretsFileResult(path=Path("/tmp/iam-ra.yaml"), encrypted=True)
        result = _make_onboard_result(secrets_file=sops)
        out = self._render(result)
        # Key SOPS field names should appear so the user knows what to reference
        assert "certificate" in out
        assert "private_key" in out
