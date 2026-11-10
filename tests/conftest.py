"""Shared pytest fixtures for iam-ra-cli tests."""

import tempfile
from pathlib import Path

import pytest
from moto import mock_aws


@pytest.fixture
def aws_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    """Mock AWS credentials for moto."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "ap-southeast-2")


@pytest.fixture
def temp_xdg_dirs(monkeypatch: pytest.MonkeyPatch):
    """Create temporary XDG directories for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        config_dir = base / "config"
        data_dir = base / "data"
        cache_dir = base / "cache"

        config_dir.mkdir()
        data_dir.mkdir()
        cache_dir.mkdir()

        monkeypatch.setenv("XDG_CONFIG_HOME", str(config_dir))
        monkeypatch.setenv("XDG_DATA_HOME", str(data_dir))

        yield {
            "config": config_dir,
            "data": data_dir,
            "cache": cache_dir,
            "base": base,
        }


@pytest.fixture
def mock_aws_context(aws_credentials, temp_xdg_dirs):
    """Create a complete mocked AWS context."""

    from iam_ra_cli.lib.aws import AwsContext

    with mock_aws():
        # Create the AwsContext
        ctx = AwsContext(region="ap-southeast-2", profile=None)

        # Pre-create bucket for tests that need it
        ctx.s3.create_bucket(
            Bucket="test-bucket",
            CreateBucketConfiguration={"LocationConstraint": "ap-southeast-2"},
        )

        yield ctx, temp_xdg_dirs


@pytest.fixture
def sample_ca_keypair():
    """Generate a sample CA keypair for testing."""
    from iam_ra_cli.lib.crypto import generate_ca

    return generate_ca(common_name="Test CA", validity_years=1)


class FakeOp:
    """Stand-in for subprocess.run in lib/onepassword.py: records every
    `op` call. `items` is what `op item list` returns; `fail_list` /
    `fail_write` make list or create fail like a locked 1Password."""

    def __init__(self) -> None:
        self.items: list[dict[str, str]] = []
        self.fail_list = False
        self.fail_write = False
        self.calls: list[dict] = []

    def __call__(self, argv: list[str], **kwargs):
        import json
        import subprocess

        self.calls.append({"argv": argv, "input": kwargs.get("input"), "kwargs": kwargs})
        if argv[1:3] == ["item", "list"]:
            if self.fail_list:
                return subprocess.CompletedProcess(argv, 1, "", "[ERROR] not signed in")
            return subprocess.CompletedProcess(argv, 0, json.dumps(self.items), "")
        if self.fail_write:
            return subprocess.CompletedProcess(argv, 1, "", "[ERROR] account is locked")
        return subprocess.CompletedProcess(argv, 0, "", "")

    @property
    def creates(self) -> list[dict]:
        return [c for c in self.calls if c["argv"][1:3] == ["item", "create"]]


@pytest.fixture
def fake_op(monkeypatch: pytest.MonkeyPatch) -> FakeOp:
    """Patch `op` (never executed) with a recording FakeOp."""
    fake = FakeOp()
    monkeypatch.setattr("iam_ra_cli.lib.onepassword.subprocess.run", fake)
    return fake
