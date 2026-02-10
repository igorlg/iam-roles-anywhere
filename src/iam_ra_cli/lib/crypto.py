"""Cryptographic operations for certificate generation."""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


@dataclass(frozen=True)
class KeyPair:
    """PEM-encoded certificate and private key."""

    certificate: str
    private_key: str


def generate_ca(
    common_name: str = "IAM Roles Anywhere CA",
    validity_years: int = 10,
) -> KeyPair:
    """Generate a self-signed CA certificate and key.

    Args:
        common_name: CA certificate CN
        validity_years: How long the CA cert is valid

    Returns:
        KeyPair with PEM-encoded certificate and private key
    """
    # Generate EC P-256 key
    private_key = ec.generate_private_key(ec.SECP256R1())

    # Build subject/issuer (same for self-signed)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )

    # Build certificate
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=validity_years * 365))
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
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    return KeyPair(certificate=cert_pem, private_key=key_pem)


def generate_host_cert(
    hostname: str,
    ca_cert_pem: str,
    ca_key_pem: str,
    validity_days: int = 365,
) -> KeyPair:
    """Generate a host certificate signed by the CA.

    Args:
        hostname: Host identifier (becomes certificate CN)
        ca_cert_pem: CA certificate in PEM format
        ca_key_pem: CA private key in PEM format
        validity_days: How long the host cert is valid

    Returns:
        KeyPair with PEM-encoded certificate and private key
    """
    # Load CA
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode())
    ca_key = serialization.load_pem_private_key(ca_key_pem.encode(), password=None)

    # Generate host key
    private_key = ec.generate_private_key(ec.SECP256R1())

    # Build subject
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        ]
    )

    # Build certificate
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=validity_days))
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
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    # Serialize to PEM
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    return KeyPair(certificate=cert_pem, private_key=key_pem)
