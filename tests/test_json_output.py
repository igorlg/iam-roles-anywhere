"""Tests for JSON output infrastructure in commands/common.py.

Covers:
- render_json: emits data with schema_version envelope, proper serialisation
  of Arn / Path / Enum / dataclass values.
- render_json_error: structured error schema for --json failures.
- handle_result: routes errors to render_json_error when as_json=True.
"""

import json
from dataclasses import dataclass
from pathlib import Path

import pytest
from click.testing import CliRunner

from iam_ra_cli.commands.common import (
    JSON_SCHEMA_VERSION,
    handle_error,
    handle_result,
    render_json,
    render_json_error,
)
from iam_ra_cli.lib.errors import (
    NotInitializedError,
    PCANotActiveError,
    RoleInUseError,
)
from iam_ra_cli.lib.result import Err, Ok
from iam_ra_cli.models import Arn

# =============================================================================
# render_json - success payload envelope
# =============================================================================


class TestRenderJsonEnvelope:
    """render_json must wrap every payload with schema_version."""

    def test_adds_schema_version_to_dict(self) -> None:
        out = render_json({"hostname": "myhost"})
        data = json.loads(out)
        assert data["schema_version"] == JSON_SCHEMA_VERSION
        assert data["hostname"] == "myhost"

    def test_schema_version_is_v1(self) -> None:
        """v1 is the current schema - locks the constant in a test."""
        assert JSON_SCHEMA_VERSION == "v1"

    def test_preserves_data_fields(self) -> None:
        payload = {
            "hostname": "myhost",
            "namespace": "default",
            "internal": {"stack_name": "iam-ra-host-myhost"},
        }
        data = json.loads(render_json(payload))
        assert data["hostname"] == "myhost"
        assert data["namespace"] == "default"
        assert data["internal"]["stack_name"] == "iam-ra-host-myhost"

    def test_output_is_valid_json(self) -> None:
        out = render_json({"hostname": "myhost"})
        # No exception = valid
        json.loads(out)

    def test_output_is_pretty_printed(self) -> None:
        """Multi-line indented output, not a minified single line."""
        out = render_json({"hostname": "myhost"})
        assert "\n" in out


class TestRenderJsonTypes:
    """render_json must handle the project's custom types."""

    def test_arn_serialises_as_string(self) -> None:
        payload = {"trust_anchor_arn": Arn("arn:aws:iam::123:role/foo")}
        data = json.loads(render_json(payload))
        assert data["trust_anchor_arn"] == "arn:aws:iam::123:role/foo"

    def test_path_serialises_as_string(self) -> None:
        payload = {"path": Path("/tmp/foo.yaml")}
        data = json.loads(render_json(payload))
        assert data["path"] == "/tmp/foo.yaml"

    def test_none_preserved(self) -> None:
        payload = {"relative_path": None}
        data = json.loads(render_json(payload))
        assert data["relative_path"] is None

    def test_nested_dict_with_arns(self) -> None:
        payload = {
            "internal": {
                "certificate_secret_arn": Arn(
                    "arn:aws:secretsmanager:ap-southeast-2:123:secret:cert"
                ),
            },
        }
        data = json.loads(render_json(payload))
        assert (
            data["internal"]["certificate_secret_arn"]
            == "arn:aws:secretsmanager:ap-southeast-2:123:secret:cert"
        )

    def test_dataclass_serialises_to_dict(self) -> None:
        @dataclass
        class Foo:
            a: str
            b: int

        out = render_json({"foo": Foo(a="hi", b=42)})
        data = json.loads(out)
        assert data["foo"] == {"a": "hi", "b": 42}

    def test_list_of_items(self) -> None:
        """For list-style commands - emit items array."""
        payload = {"items": [{"name": "a"}, {"name": "b"}]}
        data = json.loads(render_json(payload))
        assert len(data["items"]) == 2
        assert data["items"][0]["name"] == "a"


# =============================================================================
# render_json_error - error shape
# =============================================================================


class TestRenderJsonError:
    """render_json_error must emit a stable error shape with type/message/fields."""

    def test_includes_schema_version(self) -> None:
        err = NotInitializedError(namespace="test")
        data = json.loads(render_json_error(err))
        assert data["schema_version"] == JSON_SCHEMA_VERSION

    def test_error_has_type_name(self) -> None:
        err = NotInitializedError(namespace="test")
        data = json.loads(render_json_error(err))
        assert data["error"]["type"] == "NotInitializedError"

    def test_error_has_human_message(self) -> None:
        """Message must match the human-readable _format_error output."""
        err = NotInitializedError(namespace="prod")
        data = json.loads(render_json_error(err))
        # _format_error for NotInitializedError includes the namespace
        assert "prod" in data["error"]["message"]
        assert "iam-ra init" in data["error"]["message"]

    def test_error_fields_match_dataclass(self) -> None:
        """Fields section exposes the dataclass attributes for structured parsing."""
        err = NotInitializedError(namespace="prod")
        data = json.loads(render_json_error(err))
        assert data["error"]["fields"]["namespace"] == "prod"

    def test_pca_not_active_error_includes_status(self) -> None:
        err = PCANotActiveError(
            pca_arn="arn:aws:acm-pca:ap-southeast-2:123:certificate-authority/abc",
            status="PENDING_CERTIFICATE",
        )
        data = json.loads(render_json_error(err))
        assert data["error"]["type"] == "PCANotActiveError"
        assert data["error"]["fields"]["status"] == "PENDING_CERTIFICATE"
        assert (
            data["error"]["fields"]["pca_arn"]
            == "arn:aws:acm-pca:ap-southeast-2:123:certificate-authority/abc"
        )

    def test_role_in_use_error_serialises_hosts_tuple(self) -> None:
        """Tuples should become JSON arrays."""
        err = RoleInUseError(role_name="readonly", hosts=("host-a", "host-b"))
        data = json.loads(render_json_error(err))
        assert data["error"]["fields"]["hosts"] == ["host-a", "host-b"]

    def test_output_is_valid_json(self) -> None:
        err = NotInitializedError(namespace="test")
        # No exception = valid
        json.loads(render_json_error(err))


# =============================================================================
# handle_result with as_json
# =============================================================================


class TestHandleResultAsJson:
    """When as_json=True, handle_result should route errors through
    render_json_error (stderr) with a non-zero exit code, and not print
    the success message on Ok."""

    def test_ok_value_returned_unchanged(self) -> None:
        """Ok(value) should just return the value; no output."""
        result = handle_result(Ok("hello"), success_message="Done!", as_json=True)
        assert result == "hello"

    def test_ok_with_as_json_suppresses_success_message(self, capsys) -> None:
        handle_result(Ok("hello"), success_message="Done!", as_json=True)
        captured = capsys.readouterr()
        # Success message would go to stderr, but as_json=True suppresses it
        assert "Done!" not in captured.err
        assert "Done!" not in captured.out

    def test_err_with_as_json_emits_json_to_stderr(self) -> None:
        """When as_json, error JSON must go to stderr (not stdout)."""
        import click

        @click.command()
        @click.option("--as-json", "as_json", is_flag=True)
        def cmd(as_json: bool) -> None:
            handle_result(
                Err(NotInitializedError(namespace="test")),
                as_json=as_json,
            )

        runner = CliRunner()
        result = runner.invoke(cmd, ["--as-json"])

        # Exit code non-zero
        assert result.exit_code != 0
        # stdout empty
        assert result.stdout == ""
        # stderr has valid JSON with the error shape
        data = json.loads(result.stderr)
        assert data["schema_version"] == JSON_SCHEMA_VERSION
        assert data["error"]["type"] == "NotInitializedError"
        assert data["error"]["fields"]["namespace"] == "test"

    def test_err_without_as_json_uses_text_stderr(self) -> None:
        """When as_json=False (default), errors keep text format on stderr."""
        import click

        @click.command()
        def cmd() -> None:
            handle_result(
                Err(NotInitializedError(namespace="test")),
                as_json=False,
            )

        runner = CliRunner()
        result = runner.invoke(cmd)

        assert result.exit_code != 0
        # Should be plain text, NOT JSON
        assert "Error:" in result.stderr
        # Must not parse as JSON
        with pytest.raises(json.JSONDecodeError):
            json.loads(result.stderr)


class TestHandleErrorAsJson:
    """handle_error is the lower-level error rendering called by handle_result.
    Test it directly for coverage of the branching logic."""

    def test_as_json_writes_json_to_stderr(self) -> None:
        import click

        @click.command()
        def cmd() -> None:
            handle_error(NotInitializedError(namespace="prod"), as_json=True)

        runner = CliRunner()
        result = runner.invoke(cmd)

        assert result.exit_code != 0
        data = json.loads(result.stderr)
        assert data["error"]["type"] == "NotInitializedError"

    def test_no_as_json_writes_text_to_stderr(self) -> None:
        import click

        @click.command()
        def cmd() -> None:
            handle_error(NotInitializedError(namespace="prod"), as_json=False)

        runner = CliRunner()
        result = runner.invoke(cmd)

        assert result.exit_code != 0
        assert "Error:" in result.stderr
        assert "prod" in result.stderr
