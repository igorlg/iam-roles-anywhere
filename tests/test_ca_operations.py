"""Tests for operations/ca.py - scoped CA operations.

Tests cover:
- Scoped path helpers (stack names, S3 keys, local paths)
- CA creation with scope parameter
- CA deletion
"""

import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
from moto import mock_aws

from iam_ra_cli.lib.aws import AwsContext
from iam_ra_cli.lib.result import Err, Ok
from iam_ra_cli.models import Arn
from iam_ra_cli.operations.ca import (
    _ca_cert_s3_key,
    _ca_key_local_path,
    _stack_name,
    create_self_signed_ca,
)


# =============================================================================
# Scoped Path Helper Tests
# =============================================================================


class TestStackName:
    """Tests for _stack_name with scope support."""

    def test_default_scope(self) -> None:
        """Default scope should produce iam-ra-{ns}-ca-default."""
        assert _stack_name("myns", "default") == "iam-ra-myns-ca-default"

    def test_custom_scope(self) -> None:
        """Custom scope should appear in stack name."""
        assert _stack_name("myns", "cert-manager") == "iam-ra-myns-ca-cert-manager"

    def test_another_scope(self) -> None:
        """Different scope name."""
        assert _stack_name("prod", "longhorn-system") == "iam-ra-prod-ca-longhorn-system"


class TestCACertS3Key:
    """Tests for _ca_cert_s3_key with scope support."""

    def test_default_scope(self) -> None:
        """Default scope S3 key includes scope in path."""
        assert _ca_cert_s3_key("myns", "default") == "myns/scopes/default/ca/certificate.pem"

    def test_custom_scope(self) -> None:
        """Custom scope S3 key."""
        assert (
            _ca_cert_s3_key("myns", "cert-manager") == "myns/scopes/cert-manager/ca/certificate.pem"
        )


class TestCAKeyLocalPath:
    """Tests for _ca_key_local_path with scope support."""

    def test_default_scope(self, monkeypatch, tmp_path) -> None:
        """Default scope local path includes scope directory."""
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
        path = _ca_key_local_path("myns", "default")
        assert path == tmp_path / "iam-ra" / "myns" / "scopes" / "default" / "ca-private-key.pem"

    def test_custom_scope(self, monkeypatch, tmp_path) -> None:
        """Custom scope local path."""
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
        path = _ca_key_local_path("myns", "cert-manager")
        assert (
            path == tmp_path / "iam-ra" / "myns" / "scopes" / "cert-manager" / "ca-private-key.pem"
        )


# =============================================================================
# CA Creation Tests
# =============================================================================


class TestCreateSelfSignedCA:
    """Tests for create_self_signed_ca with scope."""

    @pytest.fixture
    def aws_env(self, monkeypatch, tmp_path):
        """Set up AWS mocking and temp dirs."""
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
        monkeypatch.setenv("AWS_DEFAULT_REGION", "ap-southeast-2")
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))

        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2")
            ctx.s3.create_bucket(
                Bucket="test-bucket",
                CreateBucketConfiguration={"LocationConstraint": "ap-southeast-2"},
            )
            yield ctx, tmp_path

    def test_creates_ca_with_default_scope(self, aws_env) -> None:
        """Should create CA using scoped paths for default scope."""
        ctx, tmp_path = aws_env

        # Mock deploy_stack since moto can't handle custom resources
        mock_outputs = {
            "TrustAnchorArn": "arn:aws:rolesanywhere:ap-southeast-2:123456789012:trust-anchor/ta-1"
        }
        with patch("iam_ra_cli.operations.ca.deploy_stack", return_value=Ok(mock_outputs)):
            result = create_self_signed_ca(ctx, "myns", "test-bucket", scope="default")

        assert isinstance(result, Ok)
        assert result.value.stack_name == "iam-ra-myns-ca-default"
        assert result.value.cert_s3_key == "myns/scopes/default/ca/certificate.pem"
        assert "scopes/default" in str(result.value.local_key_path)

    def test_creates_ca_with_custom_scope(self, aws_env) -> None:
        """Should create CA using scoped paths for custom scope."""
        ctx, tmp_path = aws_env

        mock_outputs = {
            "TrustAnchorArn": "arn:aws:rolesanywhere:ap-southeast-2:123456789012:trust-anchor/ta-2"
        }
        with patch("iam_ra_cli.operations.ca.deploy_stack", return_value=Ok(mock_outputs)):
            result = create_self_signed_ca(ctx, "myns", "test-bucket", scope="cert-manager")

        assert isinstance(result, Ok)
        assert result.value.stack_name == "iam-ra-myns-ca-cert-manager"
        assert result.value.cert_s3_key == "myns/scopes/cert-manager/ca/certificate.pem"

    def test_uploads_cert_to_scoped_s3_path(self, aws_env) -> None:
        """Should upload CA cert to scoped S3 path."""
        ctx, tmp_path = aws_env

        mock_outputs = {
            "TrustAnchorArn": "arn:aws:rolesanywhere:ap-southeast-2:123456789012:trust-anchor/ta-1"
        }
        with patch("iam_ra_cli.operations.ca.deploy_stack", return_value=Ok(mock_outputs)):
            create_self_signed_ca(ctx, "myns", "test-bucket", scope="cert-manager")

        # Verify the cert was uploaded to the scoped S3 path
        obj = ctx.s3.get_object(
            Bucket="test-bucket",
            Key="myns/scopes/cert-manager/ca/certificate.pem",
        )
        cert_content = obj["Body"].read().decode()
        assert "BEGIN CERTIFICATE" in cert_content

    def test_saves_key_to_scoped_local_path(self, aws_env) -> None:
        """Should save CA private key to scoped local path."""
        ctx, tmp_path = aws_env

        mock_outputs = {
            "TrustAnchorArn": "arn:aws:rolesanywhere:ap-southeast-2:123456789012:trust-anchor/ta-1"
        }
        with patch("iam_ra_cli.operations.ca.deploy_stack", return_value=Ok(mock_outputs)):
            result = create_self_signed_ca(ctx, "myns", "test-bucket", scope="cert-manager")

        assert isinstance(result, Ok)
        assert result.value.local_key_path.exists()
        key_content = result.value.local_key_path.read_text()
        assert "BEGIN" in key_content

    def test_passes_scope_tag_to_cfn(self, aws_env) -> None:
        """Should include scope in CFN stack tags."""
        ctx, tmp_path = aws_env

        mock_outputs = {
            "TrustAnchorArn": "arn:aws:rolesanywhere:ap-southeast-2:123456789012:trust-anchor/ta-1"
        }
        with patch("iam_ra_cli.operations.ca.deploy_stack", return_value=Ok(mock_outputs)) as mock:
            create_self_signed_ca(ctx, "myns", "test-bucket", scope="cert-manager")

        # Verify tags include scope
        call_kwargs = mock.call_args
        tags = call_kwargs.kwargs.get("tags") or call_kwargs[1].get("tags")
        assert tags["iam-ra:scope"] == "cert-manager"

    def test_cn_includes_scope(self, aws_env) -> None:
        """Should include scope in the CA certificate common name."""
        ctx, tmp_path = aws_env

        mock_outputs = {
            "TrustAnchorArn": "arn:aws:rolesanywhere:ap-southeast-2:123456789012:trust-anchor/ta-1"
        }
        with patch("iam_ra_cli.operations.ca.deploy_stack", return_value=Ok(mock_outputs)):
            with patch("iam_ra_cli.operations.ca.crypto.generate_ca") as mock_gen:
                from iam_ra_cli.lib.crypto import KeyPair

                mock_gen.return_value = KeyPair(
                    certificate="-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----",
                    private_key="-----BEGIN EC PRIVATE KEY-----\nfake\n-----END EC PRIVATE KEY-----",
                )
                create_self_signed_ca(ctx, "myns", "test-bucket", scope="cert-manager")

        mock_gen.assert_called_once()
        call_kwargs = mock_gen.call_args
        cn = call_kwargs.kwargs.get("common_name") or call_kwargs[0][0]
        assert "cert-manager" in cn
