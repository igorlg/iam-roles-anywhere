"""Tests for operations/host.py - PCA host onboarding.

Tests focus on the PCA path (onboard_host_pca) which:
1. Generates a host keypair and CSR locally
2. Calls ACM PCA IssueCertificate + waits + GetCertificate
3. Uploads cert + key to S3
4. Deploys the host CFN stack (mocked - moto can't handle custom resources)
"""

from unittest.mock import patch

import pytest
from cryptography import x509
from moto import mock_aws

from iam_ra_cli.lib.aws import AwsContext
from iam_ra_cli.lib.errors import (
    PCADescribeError,
    PCAGetCertError,
    PCAIssueCertError,
    PCANotActiveError,
    PCATimeoutError,
)
from iam_ra_cli.lib.result import Err, Ok
from iam_ra_cli.operations.host import onboard_host_pca

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def aws_env(monkeypatch):
    """Set up mocked AWS environment with S3 bucket and an ACTIVE PCA."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "ap-southeast-2")

    with mock_aws():
        ctx = AwsContext(region="ap-southeast-2")
        ctx.s3.create_bucket(
            Bucket="test-bucket",
            CreateBucketConfiguration={"LocationConstraint": "ap-southeast-2"},
        )

        # Create a PCA for tests to issue against
        pca_resp = ctx.acm_pca.create_certificate_authority(
            CertificateAuthorityConfiguration={
                "KeyAlgorithm": "EC_prime256v1",
                "SigningAlgorithm": "SHA256WITHECDSA",
                "Subject": {"CommonName": "Test Root CA"},
            },
            CertificateAuthorityType="ROOT",
        )
        pca_arn = pca_resp["CertificateAuthorityArn"]

        # Activate the PCA - real-world onboard requires status=ACTIVE
        ctx.acm_pca.update_certificate_authority(
            CertificateAuthorityArn=pca_arn, Status="ACTIVE"
        )

        yield ctx, pca_arn


@pytest.fixture
def aws_env_pending_pca(monkeypatch):
    """Same as aws_env but the PCA is left in PENDING_CERTIFICATE status."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "ap-southeast-2")

    with mock_aws():
        ctx = AwsContext(region="ap-southeast-2")
        ctx.s3.create_bucket(
            Bucket="test-bucket",
            CreateBucketConfiguration={"LocationConstraint": "ap-southeast-2"},
        )

        pca_resp = ctx.acm_pca.create_certificate_authority(
            CertificateAuthorityConfiguration={
                "KeyAlgorithm": "EC_prime256v1",
                "SigningAlgorithm": "SHA256WITHECDSA",
                "Subject": {"CommonName": "Test Root CA"},
            },
            CertificateAuthorityType="ROOT",
        )
        pca_arn = pca_resp["CertificateAuthorityArn"]
        # No activation - status stays PENDING_CERTIFICATE

        yield ctx, pca_arn


MOCK_STACK_OUTPUTS = {
    "CertificateSecretArn": (
        "arn:aws:secretsmanager:ap-southeast-2:123456789012:secret:iam-ra-cert-abc"
    ),
    "PrivateKeySecretArn": (
        "arn:aws:secretsmanager:ap-southeast-2:123456789012:secret:iam-ra-key-xyz"
    ),
}


# =============================================================================
# Happy-path tests
# =============================================================================


class TestOnboardHostPCASuccess:
    """onboard_host_pca end-to-end success with moto PCA."""

    def test_returns_host_result_on_success(self, aws_env) -> None:
        """Successful onboard returns a HostResult with expected ARNs."""
        ctx, pca_arn = aws_env

        with patch(
            "iam_ra_cli.operations.host.deploy_stack",
            return_value=Ok(MOCK_STACK_OUTPUTS),
        ):
            result = onboard_host_pca(
                ctx,
                namespace="myns",
                hostname="myhost",
                pca_arn=pca_arn,
                bucket_name="test-bucket",
                validity_days=365,
            )

        assert isinstance(result, Ok)
        assert result.value.hostname == "myhost"
        assert result.value.stack_name == "iam-ra-myns-host-myhost"
        assert "iam-ra-cert-abc" in str(result.value.certificate_secret_arn)

    def test_uploads_cert_to_scoped_s3_path(self, aws_env) -> None:
        """Host cert from PCA should be uploaded to the correct S3 path."""
        ctx, pca_arn = aws_env

        with patch(
            "iam_ra_cli.operations.host.deploy_stack",
            return_value=Ok(MOCK_STACK_OUTPUTS),
        ):
            onboard_host_pca(
                ctx,
                namespace="myns",
                hostname="myhost",
                pca_arn=pca_arn,
                bucket_name="test-bucket",
                validity_days=365,
            )

        obj = ctx.s3.get_object(
            Bucket="test-bucket",
            Key="myns/hosts/myhost/certificate.pem",
        )
        cert_pem = obj["Body"].read().decode()
        assert "BEGIN CERTIFICATE" in cert_pem

        # The cert should be parseable as a real x509 cert
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        # PCA-issued certs won't have our hostname as CN (PCA templates override
        # the subject), but the cert must still be valid x509.
        assert cert.serial_number > 0

    def test_uploads_private_key_to_scoped_s3_path(self, aws_env) -> None:
        """Host private key should be uploaded to the correct S3 path."""
        ctx, pca_arn = aws_env

        with patch(
            "iam_ra_cli.operations.host.deploy_stack",
            return_value=Ok(MOCK_STACK_OUTPUTS),
        ):
            onboard_host_pca(
                ctx,
                namespace="myns",
                hostname="myhost",
                pca_arn=pca_arn,
                bucket_name="test-bucket",
                validity_days=365,
            )

        obj = ctx.s3.get_object(
            Bucket="test-bucket",
            Key="myns/hosts/myhost/private-key.pem",
        )
        key_pem = obj["Body"].read().decode()
        assert "BEGIN EC PRIVATE KEY" in key_pem

    def test_passes_correct_parameters_to_cfn_deploy(self, aws_env) -> None:
        """CFN deploy should receive the expected stack parameters and tags."""
        ctx, pca_arn = aws_env

        with patch(
            "iam_ra_cli.operations.host.deploy_stack",
            return_value=Ok(MOCK_STACK_OUTPUTS),
        ) as mock_deploy:
            onboard_host_pca(
                ctx,
                namespace="myns",
                hostname="myhost",
                pca_arn=pca_arn,
                bucket_name="test-bucket",
                validity_days=365,
            )

        mock_deploy.assert_called_once()
        call_kwargs = mock_deploy.call_args.kwargs
        assert call_kwargs["stack_name"] == "iam-ra-myns-host-myhost"
        assert call_kwargs["parameters"]["Namespace"] == "myns"
        assert call_kwargs["parameters"]["Hostname"] == "myhost"
        assert call_kwargs["parameters"]["CertificateS3Key"] == "myns/hosts/myhost/certificate.pem"
        assert call_kwargs["parameters"]["PrivateKeyS3Key"] == "myns/hosts/myhost/private-key.pem"
        assert call_kwargs["tags"]["iam-ra:namespace"] == "myns"
        assert call_kwargs["tags"]["iam-ra:hostname"] == "myhost"

    def test_calls_pca_issue_certificate_with_csr(self, aws_env) -> None:
        """Verify PCA IssueCertificate is called with a valid CSR containing the hostname."""
        ctx, pca_arn = aws_env

        captured = {}
        real_issue = ctx.acm_pca.issue_certificate

        def spy_issue(**kwargs):
            captured.update(kwargs)
            return real_issue(**kwargs)

        with (
            patch(
                "iam_ra_cli.operations.host.deploy_stack",
                return_value=Ok(MOCK_STACK_OUTPUTS),
            ),
            patch.object(ctx.acm_pca, "issue_certificate", side_effect=spy_issue),
        ):
            onboard_host_pca(
                ctx,
                namespace="myns",
                hostname="myhost",
                pca_arn=pca_arn,
                bucket_name="test-bucket",
                validity_days=90,
            )

        assert captured["CertificateAuthorityArn"] == pca_arn
        assert captured["Validity"] == {"Value": 90, "Type": "DAYS"}
        assert captured["TemplateArn"].endswith("EndEntityClientAuthCertificate/V1")

        # Parse the CSR that was sent - its CN should be our hostname
        csr = x509.load_pem_x509_csr(captured["Csr"])
        cn = csr.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0]
        assert cn.value == "myhost"

    def test_queries_pca_for_signing_algorithm(self, aws_env) -> None:
        """Signing algorithm must come from DescribeCertificateAuthority, not hardcoded."""
        ctx, pca_arn = aws_env

        captured = {}
        real_issue = ctx.acm_pca.issue_certificate

        def spy_issue(**kwargs):
            captured.update(kwargs)
            return real_issue(**kwargs)

        with (
            patch(
                "iam_ra_cli.operations.host.deploy_stack",
                return_value=Ok(MOCK_STACK_OUTPUTS),
            ),
            patch.object(ctx.acm_pca, "issue_certificate", side_effect=spy_issue),
        ):
            onboard_host_pca(
                ctx,
                namespace="myns",
                hostname="myhost",
                pca_arn=pca_arn,
                bucket_name="test-bucket",
                validity_days=365,
            )

        # Our test PCA was created with SHA256WITHECDSA
        assert captured["SigningAlgorithm"] == "SHA256WITHECDSA"


# =============================================================================
# Error path tests
# =============================================================================


class TestOnboardHostPCAErrors:
    """Error paths return typed Err values (no exceptions)."""

    def test_describe_ca_failure_returns_pca_describe_error(self, aws_env) -> None:
        """If describe_certificate_authority fails, return PCADescribeError."""
        ctx, pca_arn = aws_env

        from botocore.exceptions import ClientError

        err = ClientError(
            {"Error": {"Code": "ResourceNotFoundException", "Message": "no such CA"}},
            "DescribeCertificateAuthority",
        )
        with patch.object(ctx.acm_pca, "describe_certificate_authority", side_effect=err):
            result = onboard_host_pca(
                ctx,
                namespace="myns",
                hostname="myhost",
                pca_arn=pca_arn,
                bucket_name="test-bucket",
            )

        assert isinstance(result, Err)
        assert isinstance(result.error, PCADescribeError)
        assert result.error.pca_arn == pca_arn

    def test_issue_certificate_failure_returns_issue_error(self, aws_env) -> None:
        """If IssueCertificate fails, return PCAIssueCertError."""
        ctx, pca_arn = aws_env

        from botocore.exceptions import ClientError

        err = ClientError(
            {"Error": {"Code": "MalformedCSRException", "Message": "bad CSR"}},
            "IssueCertificate",
        )
        with patch.object(ctx.acm_pca, "issue_certificate", side_effect=err):
            result = onboard_host_pca(
                ctx,
                namespace="myns",
                hostname="myhost",
                pca_arn=pca_arn,
                bucket_name="test-bucket",
            )

        assert isinstance(result, Err)
        assert isinstance(result.error, PCAIssueCertError)
        assert result.error.pca_arn == pca_arn

    def test_get_certificate_failure_returns_get_error(self, aws_env) -> None:
        """If GetCertificate fails (after waiter succeeds), return PCAGetCertError.

        The waiter internally polls via get_certificate, so we mock the waiter
        to succeed immediately and then fail our direct GetCertificate call.
        """
        ctx, pca_arn = aws_env

        from unittest.mock import MagicMock

        from botocore.exceptions import ClientError

        mock_waiter = MagicMock()
        mock_waiter.wait.return_value = None

        err = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
            "GetCertificate",
        )
        with (
            patch.object(ctx.acm_pca, "get_waiter", return_value=mock_waiter),
            patch.object(ctx.acm_pca, "get_certificate", side_effect=err),
        ):
            result = onboard_host_pca(
                ctx,
                namespace="myns",
                hostname="myhost",
                pca_arn=pca_arn,
                bucket_name="test-bucket",
            )

        assert isinstance(result, Err)
        assert isinstance(result.error, PCAGetCertError)
        assert result.error.pca_arn == pca_arn

    def test_waiter_timeout_returns_timeout_error(self, aws_env) -> None:
        """If the certificate_issued waiter times out, return PCATimeoutError."""
        ctx, pca_arn = aws_env

        from unittest.mock import MagicMock

        from botocore.exceptions import WaiterError

        mock_waiter = MagicMock()
        mock_waiter.wait.side_effect = WaiterError(
            name="certificate_issued",
            reason="Max attempts exceeded",
            last_response={},
        )

        with patch.object(ctx.acm_pca, "get_waiter", return_value=mock_waiter):
            result = onboard_host_pca(
                ctx,
                namespace="myns",
                hostname="myhost",
                pca_arn=pca_arn,
                bucket_name="test-bucket",
            )

        assert isinstance(result, Err)
        assert isinstance(result.error, PCATimeoutError)
        assert result.error.pca_arn == pca_arn


# =============================================================================
# PCA status preflight check
# =============================================================================


class TestOnboardHostPCAStatusCheck:
    """onboard_host_pca should fail fast if PCA is not ACTIVE."""

    def test_pending_certificate_pca_returns_not_active_error(
        self, aws_env_pending_pca
    ) -> None:
        """PENDING_CERTIFICATE status should short-circuit with PCANotActiveError."""
        ctx, pca_arn = aws_env_pending_pca

        result = onboard_host_pca(
            ctx,
            namespace="myns",
            hostname="myhost",
            pca_arn=pca_arn,
            bucket_name="test-bucket",
        )

        assert isinstance(result, Err)
        assert isinstance(result.error, PCANotActiveError)
        assert result.error.status == "PENDING_CERTIFICATE"
        assert result.error.pca_arn == pca_arn

    def test_disabled_pca_returns_not_active_error(self, aws_env) -> None:
        """DISABLED status should short-circuit with PCANotActiveError."""
        ctx, pca_arn = aws_env
        ctx.acm_pca.update_certificate_authority(
            CertificateAuthorityArn=pca_arn, Status="DISABLED"
        )

        result = onboard_host_pca(
            ctx,
            namespace="myns",
            hostname="myhost",
            pca_arn=pca_arn,
            bucket_name="test-bucket",
        )

        assert isinstance(result, Err)
        assert isinstance(result.error, PCANotActiveError)
        assert result.error.status == "DISABLED"

    def test_pending_pca_does_not_issue_certificate(self, aws_env_pending_pca) -> None:
        """The status check must fire before we call issue_certificate."""
        ctx, pca_arn = aws_env_pending_pca

        with patch.object(
            ctx.acm_pca, "issue_certificate", wraps=ctx.acm_pca.issue_certificate
        ) as spy_issue:
            onboard_host_pca(
                ctx,
                namespace="myns",
                hostname="myhost",
                pca_arn=pca_arn,
                bucket_name="test-bucket",
            )

        spy_issue.assert_not_called()
