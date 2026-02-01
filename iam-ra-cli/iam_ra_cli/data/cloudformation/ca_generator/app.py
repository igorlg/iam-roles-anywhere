"""
CA Generator Lambda Function

Generates a self-managed Certificate Authority for IAM Roles Anywhere.
Used as a CloudFormation custom resource during account stack creation.

This Lambda:
1. Generates an EC P-256 CA key pair
2. Creates a self-signed CA certificate (default 10 years validity)
3. Returns CACertificate and CAPrivateKey via helper.Data
4. CloudFormation creates the Secrets Manager secret and SSM parameter

Environment Variables:
- LOG_LEVEL: Logging level (default: INFO)
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Any, Dict

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


def generate_ca_certificate(validity_years: int = 10) -> tuple[str, str]:
    """
    Generate a self-signed CA certificate and private key.

    Args:
        validity_years: Certificate validity period in years

    Returns:
        Tuple of (certificate_pem, private_key_pem)
    """
    logger.info(f"Generating EC P-256 CA key pair with {validity_years} year validity")

    # Generate EC P-256 private key
    private_key = ec.generate_private_key(ec.SECP256R1())

    # Create subject/issuer (same for self-signed)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "IAM Roles Anywhere"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Self-Managed CA"),
        ]
    )

    # Build certificate
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=validity_years * 365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    # Serialize to PEM
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    logger.info("CA certificate generated successfully")
    logger.info(f"Serial Number: {cert.serial_number}")
    logger.info(f"Not Before: {cert.not_valid_before}")
    logger.info(f"Not After: {cert.not_valid_after}")

    return cert_pem, key_pem


@helper.create
def create(event: Dict[str, Any], context: Any) -> str:
    """
    Handle CREATE event - generate new CA.

    Returns CACertificate and CAPrivateKey via helper.Data for CloudFormation
    to use when creating Secrets Manager secret and SSM parameter.

    Args:
        event: CloudFormation event
        context: Lambda context

    Returns:
        Physical resource ID
    """
    logger.info("Handling CREATE event")
    properties = event["ResourceProperties"]

    # Get parameters
    validity_years = int(properties.get("ValidityYears", 10))

    # Generate CA certificate and key
    cert_pem, key_pem = generate_ca_certificate(validity_years)

    # Return via helper.Data - CloudFormation creates the secrets/parameters
    helper.Data["CACertificate"] = cert_pem
    helper.Data["CAPrivateKey"] = key_pem

    logger.info("CA generation completed successfully")
    return "ca-certificate-generated"


@helper.update
def update(event: Dict[str, Any], context: Any) -> str:
    """
    Handle UPDATE event - regenerate CA if validity changed.

    Args:
        event: CloudFormation event
        context: Lambda context

    Returns:
        Physical resource ID
    """
    logger.info("Handling UPDATE event")

    # For simplicity, treat update as delete + create
    # This will regenerate the CA with new parameters
    logger.warning("UPDATE will regenerate CA - this will invalidate all host certificates!")

    properties = event["ResourceProperties"]
    old_properties = event.get("OldResourceProperties", {})

    # Check if ValidityYears changed
    new_validity = int(properties.get("ValidityYears", 10))
    old_validity = int(old_properties.get("ValidityYears", 10))

    if new_validity != old_validity:
        logger.info(f"ValidityYears changed from {old_validity} to {new_validity}, regenerating CA")
        return create(event, context)
    else:
        logger.info("No changes detected, skipping CA regeneration")
        return event["PhysicalResourceId"]


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
    logger.info("Handling DELETE event")
    logger.info("CloudFormation will manage secret/parameter deletion")


@helper.poll_create
def poll_create(event: Dict[str, Any], context: Any) -> bool:
    """
    Poll for CREATE completion.

    Not needed for CA generation (synchronous operation),
    but included for consistency with certificate_issuer.

    Args:
        event: CloudFormation event
        context: Lambda context

    Returns:
        True (always complete)
    """
    logger.info("Polling CREATE - CA generation is synchronous, returning True")
    return True


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
            self.function_name = "ca-generator-test"
            self.function_version = "1"
            self.invoked_function_arn = "arn:aws:lambda:us-east-1:123456789012:function:test"
            self.memory_limit_in_mb = 128
            self.aws_request_id = "test-request-id"
            self.log_group_name = "/aws/lambda/test"
            self.log_stream_name = "test-stream"

        def get_remaining_time_in_millis(self):
            return 300000

    # Test CA generation
    test_event = {
        "RequestType": "Create",
        "ResourceProperties": {"ValidityYears": "10"},
        "ResponseURL": "http://pre-signed-S3-url-for-response",
        "StackId": "arn:aws:cloudformation:us-east-1:123456789012:stack/test-stack/guid",
        "RequestId": "unique-id",
        "LogicalResourceId": "CAGenerator",
        "ResourceType": "Custom::CAGenerator",
    }

    context = MockLambdaContext()

    print("Testing CA Generator Lambda...")
    print(f"Event: {json.dumps(test_event, indent=2)}")
    print("\nGenerating CA...")

    cert_pem, key_pem = generate_ca_certificate(10)

    print("\nCA Certificate (first 200 chars):")
    print(cert_pem[:200])
    print("\nCA Private Key (first 200 chars):")
    print(key_pem[:200])
    print("\nCA generation test completed successfully!")
