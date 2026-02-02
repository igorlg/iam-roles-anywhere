"""
Certificate Issuer Lambda Function

Issues host certificates for IAM Roles Anywhere.
Used as a CloudFormation custom resource during host stack creation.

Supports CA modes:
1. self-managed: Signs certificates using CA key from Secrets Manager
2. pca-create: Issues certificates via ACM Private CA (created by rootca stack)
3. pca-existing: Issues certificates via existing ACM Private CA
4. aws-pca: (legacy) Same as pca-existing

This Lambda:
1. Generates an EC P-256 host key pair
2. Creates a CSR with CN=hostname
3. Signs certificate (self-managed) or issues via PCA
4. Stores certificate and private key in Secrets Manager
5. Stores ARNs in SSM Parameter Store

Environment Variables:
- LOG_LEVEL: Logging level (default: INFO)
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple

import boto3
from crhelper import CfnResource
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

# Initialize logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Initialize crhelper
helper = CfnResource(
    json_logging=True,
    log_level="INFO",
    boto_level="CRITICAL",
    sleep_on_delete=5,
)

# AWS client for ACM PCA
acm_pca = boto3.client("acm-pca")


def generate_host_key_and_csr(hostname: str) -> Tuple[str, str, bytes]:
    """
    Generate EC P-256 key pair and CSR for a host.

    Args:
        hostname: The hostname to use as CN

    Returns:
        Tuple of (private_key_pem, csr_pem, csr_der)
    """
    logger.info(f"Generating EC P-256 key pair for hostname: {hostname}")

    # Generate EC P-256 private key
    private_key = ec.generate_private_key(ec.SECP256R1())

    # Create CSR
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, hostname),
                ]
            )
        )
        .sign(private_key, hashes.SHA256())
    )

    # Serialize private key to PEM
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    # CSR in PEM format (required by ACM PCA API)
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    # CSR in DER format (used by self-managed CA)
    csr_der = csr.public_bytes(serialization.Encoding.DER)

    logger.info(f"Generated key and CSR for: {hostname}")
    return key_pem, csr_pem, csr_der


def sign_certificate_self_managed(
    csr_der: bytes,
    hostname: str,
    ca_key_pem: str,
    ca_cert_pem: str,
    validity_days: int = 365,
) -> str:
    """
    Sign a certificate using the self-managed CA.

    Args:
        csr_der: Certificate Signing Request in DER format
        hostname: Hostname for logging
        ca_key_pem: CA private key in PEM format (passed via CloudFormation)
        ca_cert_pem: CA certificate in PEM format (passed via CloudFormation)
        validity_days: Certificate validity in days

    Returns:
        Signed certificate PEM
    """
    logger.info(f"Signing certificate for {hostname} using self-managed CA")

    if not ca_key_pem:
        raise ValueError("CA private key not provided. Was rootca stack deployed with self-managed mode?")
    if not ca_cert_pem:
        raise ValueError("CA certificate not provided. Was rootca stack deployed with self-managed mode?")

    # Load CA key and certificate
    ca_key = serialization.load_pem_private_key(ca_key_pem.encode(), password=None)
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode())

    # Load CSR
    csr = x509.load_der_x509_csr(csr_der)

    # Build and sign certificate
    cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=validity_days))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    logger.info(f"Certificate signed for {hostname}")
    logger.info(f"Serial Number: {cert.serial_number}")
    logger.info(f"Not Before: {cert.not_valid_before}")
    logger.info(f"Not After: {cert.not_valid_after}")

    return cert_pem


def get_pca_signing_algorithm(pca_arn: str) -> str:
    """
    Get the appropriate signing algorithm for a PCA based on its key type.

    Args:
        pca_arn: ARN of the ACM Private CA

    Returns:
        Signing algorithm string (e.g., SHA256WITHRSA, SHA256WITHECDSA)
    """
    try:
        response = acm_pca.describe_certificate_authority(
            CertificateAuthorityArn=pca_arn
        )
        key_algorithm = response["CertificateAuthority"]["CertificateAuthorityConfiguration"]["KeyAlgorithm"]
        logger.info(f"PCA key algorithm: {key_algorithm}")

        # Map key algorithm to signing algorithm
        if key_algorithm.startswith("RSA"):
            return "SHA256WITHRSA"
        elif key_algorithm.startswith("EC"):
            return "SHA256WITHECDSA"
        else:
            logger.warning(f"Unknown key algorithm {key_algorithm}, defaulting to SHA256WITHRSA")
            return "SHA256WITHRSA"
    except ClientError as e:
        logger.error(f"Failed to describe PCA: {e}")
        raise


def issue_certificate_pca(
    csr_pem: str,
    pca_arn: str,
    hostname: str,
    validity_days: int = 365,
) -> str:
    """
    Issue a certificate using AWS Private CA.

    Args:
        csr_pem: Certificate Signing Request in PEM format
        pca_arn: ARN of the ACM Private CA
        hostname: Hostname for logging
        validity_days: Certificate validity in days

    Returns:
        Certificate ARN (certificate retrieval is async, handled by poll_create)
    """
    logger.info(f"Issuing certificate for {hostname} via ACM PCA: {pca_arn}")

    # Detect signing algorithm based on PCA key type
    signing_algorithm = get_pca_signing_algorithm(pca_arn)
    logger.info(f"Using signing algorithm: {signing_algorithm}")

    try:
        response = acm_pca.issue_certificate(
            CertificateAuthorityArn=pca_arn,
            Csr=csr_pem,
            SigningAlgorithm=signing_algorithm,
            Validity={"Type": "DAYS", "Value": validity_days},
            IdempotencyToken=hostname[:36],  # Max 36 chars
        )
        cert_arn = response["CertificateArn"]
        logger.info(f"Certificate issuance requested: {cert_arn}")
        return cert_arn
    except ClientError as e:
        logger.error(f"Failed to issue certificate via PCA: {e}")
        raise


def get_pca_certificate(pca_arn: str, cert_arn: str) -> Optional[str]:
    """
    Retrieve a certificate from ACM PCA.

    Args:
        pca_arn: ARN of the ACM Private CA
        cert_arn: ARN of the certificate to retrieve

    Returns:
        Certificate PEM if ready, None if still pending
    """
    try:
        response = acm_pca.get_certificate(
            CertificateAuthorityArn=pca_arn,
            CertificateArn=cert_arn,
        )
        # Combine certificate and chain
        cert_pem = response["Certificate"]
        if "CertificateChain" in response:
            cert_pem += "\n" + response["CertificateChain"]
        return cert_pem
    except acm_pca.exceptions.RequestInProgressException:
        logger.info("Certificate issuance still in progress...")
        return None
    except Exception as e:
        logger.error(f"Failed to retrieve certificate: {e}")
        raise


@helper.create
def create(event: Dict[str, Any], context: Any) -> str:
    """
    Handle CREATE event - generate and sign host certificate.

    Returns certificate and private key via helper.Data for CloudFormation
    to use when creating Secrets Manager secrets.

    Args:
        event: CloudFormation event
        context: Lambda context

    Returns:
        Physical resource ID (hostname)
    """
    logger.info("Handling CREATE event")
    properties = event["ResourceProperties"]

    # Extract parameters
    hostname = properties["Hostname"]
    ca_mode = properties.get("CAMode", "self-managed")
    pca_arn = properties.get("PCAArn", "")
    validity_days = int(properties.get("ValidityDays", 365))

    # CA credentials (passed via CloudFormation {{resolve:...}} for self-managed mode)
    ca_private_key = properties.get("CAPrivateKey", "")
    ca_certificate = properties.get("CACertificate", "")

    logger.info(f"Processing host: {hostname}, CA mode: {ca_mode}")

    # Generate key pair and CSR (both PEM and DER formats)
    key_pem, csr_pem, csr_der = generate_host_key_and_csr(hostname)

    # Store in helper data for polling and output
    helper.Data["PrivateKey"] = key_pem
    helper.Data["Hostname"] = hostname

    # Normalize CA mode - pca-create and pca-existing both use PCA
    use_pca = ca_mode in ("aws-pca", "pca-create", "pca-existing")

    if ca_mode == "self-managed":
        # Sign certificate immediately using CA credentials from CloudFormation
        cert_pem = sign_certificate_self_managed(
            csr_der, hostname, ca_private_key, ca_certificate, validity_days
        )

        # Return certificate via helper.Data - CloudFormation creates the secrets
        helper.Data["Certificate"] = cert_pem

        logger.info(f"Certificate issued for {hostname} (self-managed mode)")
        return hostname

    elif use_pca:
        if not pca_arn:
            raise ValueError(f"PCAArn is required for {ca_mode} mode")

        # Issue certificate via PCA (async) - uses PEM format
        cert_arn = issue_certificate_pca(csr_pem, pca_arn, hostname, validity_days)
        helper.Data["PCACertificateArn"] = cert_arn
        helper.Data["PCAArn"] = pca_arn

        logger.info(f"Certificate issuance requested for {hostname} ({ca_mode} mode)")
        # Return None to trigger polling
        return None

    else:
        raise ValueError(f"Invalid CAMode: {ca_mode}")


@helper.poll_create
def poll_create(event: Dict[str, Any], context: Any) -> Optional[str]:
    """
    Poll for CREATE completion (AWS PCA mode only).

    Args:
        event: CloudFormation event with CrHelperData
        context: Lambda context

    Returns:
        hostname if complete, None if still waiting
    """
    logger.info("Polling CREATE for PCA certificate")

    # Get stored data from event
    data = event.get("CrHelperData", {})
    hostname = data.get("Hostname")
    pca_arn = data.get("PCAArn")
    cert_arn = data.get("PCACertificateArn")
    key_pem = data.get("PrivateKey")

    if not all([hostname, pca_arn, cert_arn, key_pem]):
        logger.error("Missing required data in CrHelperData")
        raise ValueError("Missing required data for poll_create")

    # Try to retrieve certificate
    cert_pem = get_pca_certificate(pca_arn, cert_arn)

    if cert_pem is None:
        # Still pending, poll again
        logger.info("Certificate still pending, will poll again")
        return None

    # Certificate is ready - return via helper.Data for CloudFormation
    helper.Data["Certificate"] = cert_pem
    helper.Data["PrivateKey"] = key_pem

    logger.info(f"Certificate issued for {hostname} (PCA mode)")
    return hostname


@helper.update
def update(event: Dict[str, Any], context: Any) -> str:
    """
    Handle UPDATE event - regenerate certificate.

    Args:
        event: CloudFormation event
        context: Lambda context

    Returns:
        Physical resource ID (hostname)
    """
    logger.info("Handling UPDATE event - regenerating certificate")

    # Treat update as create (regenerate certificate)
    return create(event, context)


@helper.delete
def delete(event: Dict[str, Any], context: Any) -> None:
    """
    Handle DELETE event.

    Args:
        event: CloudFormation event
        context: Lambda context

    Note:
        CloudFormation manages all resources (secrets, SSM params).
        This handler just logs the deletion.
    """
    hostname = event.get("PhysicalResourceId", "unknown")
    logger.info(f"DELETE event for host: {hostname}")


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda entry point.

    Args:
        event: CloudFormation event
        context: Lambda context

    Returns:
        CloudFormation response
    """
    logger.info(f"Received event: {json.dumps(event)}")
    helper(event, context)


# For local testing
if __name__ == "__main__":

    class MockLambdaContext:
        def __init__(self):
            self.function_name = "certificate-issuer-test"
            self.function_version = "1"
            self.invoked_function_arn = "arn:aws:lambda:us-east-1:123456789012:function:test"
            self.memory_limit_in_mb = 128
            self.aws_request_id = "test-request-id"
            self.log_group_name = "/aws/lambda/test"
            self.log_stream_name = "test-stream"

        def get_remaining_time_in_millis(self):
            return 300000

    # Test key/CSR generation
    print("Testing Certificate Issuer Lambda...")
    print("\nGenerating key pair and CSR for test-host...")

    key_pem, csr_pem, csr_der = generate_host_key_and_csr("test-host")

    print(f"\nPrivate Key (first 200 chars):\n{key_pem[:200]}")
    print(f"\nCSR (PEM, first 200 chars):\n{csr_pem[:200]}")
    print(f"\nCSR (DER, first 100 bytes): {csr_der[:100].hex()}")
    print("\nKey/CSR generation test completed successfully!")
