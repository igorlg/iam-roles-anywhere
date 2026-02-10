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
    import boto3

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
