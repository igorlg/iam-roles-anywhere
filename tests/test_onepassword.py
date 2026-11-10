"""Tests for the 1Password secrets backend (`host onboard --secrets-backend 1password`).

`op` is never executed (see the `fake_op` fixture). The central contract:
secret values reach `op` only on stdin, as a JSON item template.
"""

import json
import subprocess
from unittest.mock import patch

import pytest
from click.testing import CliRunner
from moto import mock_aws

from iam_ra_cli.commands.host import _render_onepassword_nix_snippet
from iam_ra_cli.lib.aws import AwsContext
from iam_ra_cli.lib.errors import OnePasswordError
from iam_ra_cli.lib.onepassword import OnePasswordItem
from iam_ra_cli.lib.result import Err, Ok
from iam_ra_cli.main import cli
from iam_ra_cli.models import Arn, Host
from iam_ra_cli.operations.secrets import store_in_onepassword
from iam_ra_cli.workflows.host import OnboardResult, RoleProfile

CERT_PEM = "-----BEGIN CERTIFICATE-----\nY2VydA==\n-----END CERTIFICATE-----\n"
KEY_PEM = "-----BEGIN PRIVATE KEY-----\nVEhST1dBV0FZ\n-----END PRIVATE KEY-----\n"
TITLE = "iam-ra-mbp-work"


@pytest.fixture
def store(aws_credentials, fake_op):
    """Call store_in_onepassword against moto-backed Secrets Manager."""
    with mock_aws():
        ctx = AwsContext(region="ap-southeast-2")
        cert = ctx.secrets.create_secret(Name="cert", SecretString=CERT_PEM)["ARN"]
        key = ctx.secrets.create_secret(Name="key", SecretString=KEY_PEM)["ARN"]
        yield lambda: store_in_onepassword(ctx, "mbp", cert, key, vault="Private", namespace="work")


class TestStoreInOnePassword:
    def test_creates_item_with_secrets_only_on_stdin(self, store, fake_op) -> None:
        fake_op.items = [{"id": "x", "title": f"{TITLE}-old"}]  # not an exact match

        assert store() == Ok(OnePasswordItem(vault="Private", title=TITLE))

        list_call, create = fake_op.calls
        assert list_call["argv"] == ["op", "item", "list", "--vault", "Private", "--format", "json"]
        # Without input, op must not inherit (and block on) our stdin.
        assert list_call["kwargs"]["stdin"] is subprocess.DEVNULL
        assert create["argv"] == ["op", "item", "create", "--vault", "Private", "-"]
        for call in fake_op.calls:
            assert "PRIVATE KEY" not in " ".join(call["argv"])
        template = json.loads(create["input"])
        fields = {f["label"]: f for f in template["fields"]}
        assert template["title"] == TITLE
        assert fields["private_key"] == {
            "id": "private_key",
            "label": "private_key",
            "type": "CONCEALED",
            "value": KEY_PEM,
        }
        assert fields["certificate"]["value"] == CERT_PEM

    @pytest.mark.parametrize("count", [1, 2])
    def test_existing_title_is_refused(self, store, fake_op, count) -> None:
        fake_op.items = [{"id": f"id{i}", "title": TITLE} for i in range(count)]

        result = store()

        assert isinstance(result, Err) and isinstance(result.error, OnePasswordError)
        assert f"{count} item(s) titled '{TITLE}'" in result.error.reason
        assert "delete them, then re-run" in result.error.reason
        assert fake_op.creates == []

    @pytest.mark.parametrize(
        ("attr", "stderr"), [("fail_list", "not signed in"), ("fail_write", "account is locked")]
    )
    def test_op_failure_is_an_error_value(self, store, fake_op, attr, stderr) -> None:
        setattr(fake_op, attr, True)

        assert store() == Err(OnePasswordError(TITLE, f"[ERROR] {stderr}"))

    def test_op_missing(self, store) -> None:
        with patch(
            "iam_ra_cli.lib.onepassword.subprocess.run", side_effect=FileNotFoundError("op")
        ):
            result = store()
        assert isinstance(result, Err) and "not found on PATH" in result.error.reason


class TestOnboardCli:
    def _invoke(self, *args: str):
        with patch("iam_ra_cli.commands.host.onboard") as onboard:
            result = CliRunner().invoke(cli, ["host", "onboard", "mbp", "--role", "admin", *args])
        return result, onboard

    @pytest.mark.parametrize(
        ("args", "message"),
        [
            (["--secrets-backend", "1password"], "requires --op-vault"),
            (
                ["--secrets-backend", "1password", "--op-vault", "V", "--sops-output", "/tmp/x"],
                "--sops-output only applies",
            ),
            (["--op-vault", "V"], "--op-vault only applies"),
        ],
    )
    def test_usage_errors(self, args, message) -> None:
        result, onboard = self._invoke(*args)
        assert result.exit_code == 2
        assert message in result.output
        onboard.assert_not_called()

    @pytest.mark.parametrize(
        ("args", "vault"),
        [(["--secrets-backend", "1password", "--op-vault", "Private"], "Private"), ([], None)],
    )
    def test_vault_reaches_workflow(self, args, vault) -> None:
        _, onboard = self._invoke(*args, "--json")
        assert onboard.call_args.args[1].op_vault == vault

    def test_nix_snippet_uses_key_ref(self) -> None:
        item = OnePasswordItem(vault="Private", title="iam-ra-mbp-default")
        result = OnboardResult(
            host=Host(
                stack_name="s",
                hostname="mbp",
                role_names=("admin",),
                certificate_secret_arn=Arn("arn:aws:secretsmanager:ap-southeast-2:1:secret:c"),
                private_key_secret_arn=Arn("arn:aws:secretsmanager:ap-southeast-2:1:secret:k"),
            ),
            secrets_file=None,
            namespace="default",
            region="ap-southeast-2",
            trust_anchor_arn=Arn("arn:aws:rolesanywhere:ap-southeast-2:1:trust-anchor/ta"),
            role_profiles=(
                RoleProfile(
                    role_name="admin",
                    role_arn=Arn("arn:aws:iam::1:role/admin"),
                    profile_arn=Arn("arn:aws:rolesanywhere:ap-southeast-2:1:profile/p"),
                ),
            ),
            onepassword_item=item,
        )
        snippet = "\n".join(_render_onepassword_nix_snippet(result, item))

        assert 'keyRef   = "op://Private/iam-ra-mbp-default/private_key";' in snippet
        assert "op read 'op://Private/iam-ra-mbp-default/certificate'" in snippet
        assert 'profileArn = "arn:aws:rolesanywhere:ap-southeast-2:1:profile/p";' in snippet
        assert "aws sts get-caller-identity --profile admin" in snippet
        assert "keyPath" not in snippet
