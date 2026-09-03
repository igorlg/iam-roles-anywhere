"""Cryptographic operations for certificate generation and CSR signing.

Two distinct roles live here:

  * **CA side** - ``generate_ca`` and ``sign_csr``. Runs on the admin
    workstation (self-signed mode) and needs the CA private key.
  * **Requester side** - ``generate_private_key``, ``build_csr``. Runs wherever
    the host key is born. From v3 that is the host itself, not the admin box.

``sign_csr`` is the single certificate-issuing primitive. It treats a CSR as a
*transport for a public key* and nothing more: the subject it certifies is the
one the caller passes in, never the one the CSR asked for. See its docstring.
"""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.types import CertificatePublicKeyTypes
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from iam_ra_cli.lib.errors import (
    CsrInvalidSignatureError,
    CsrParseError,
    CsrUnsupportedKeyError,
)
from iam_ra_cli.lib.result import Err, Ok, Result

# Curves acceptable in a host CSR. IAM Roles Anywhere signs CreateSession with
# ECDSA-SHA256 or RSA-SHA256, so the curve must be one the helper can use.
_ALLOWED_EC_CURVES = frozenset({"secp256r1", "secp384r1", "secp521r1"})

# Minimum RSA modulus size accepted in a host CSR.
_MIN_RSA_KEY_SIZE = 2048

# Errors sign_csr can return when refusing a CSR.
type SignCsrError = CsrParseError | CsrInvalidSignatureError | CsrUnsupportedKeyError


@dataclass(frozen=True)
class KeyPair:
    """PEM-encoded certificate and private key."""

    certificate: str
    private_key: str


@dataclass(frozen=True)
class HostKeyAndCsr:
    """Host private key and CSR (Certificate Signing Request).

    Used when the host certificate must be signed by an external CA
    (e.g., ACM Private CA via IssueCertificate API) rather than locally.
    """

    private_key_pem: str
    csr_pem: str


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


# =============================================================================
# Requester side - key and CSR generation
# =============================================================================


def generate_private_key() -> ec.EllipticCurvePrivateKey:
    """Generate a fresh EC P-256 private key.

    P-256 is what IAM Roles Anywhere and the credential helper handle best,
    and matches every certificate this project has issued.
    """
    return ec.generate_private_key(ec.SECP256R1())


def serialize_private_key(private_key: ec.EllipticCurvePrivateKey) -> str:
    """Serialise a private key to unencrypted SEC1 PEM.

    ``TraditionalOpenSSL`` for an EC key is SEC1 (``-----BEGIN EC PRIVATE
    KEY-----``). This is deliberate and load-bearing: macOS ``security import``
    accepts a bare SEC1 EC key but **rejects** the PKCS#8 form
    (``-----BEGIN PRIVATE KEY-----``). Do not "modernise" this to PKCS#8
    without re-testing the macosKeychain backend.
    """
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


def build_csr(private_key: ec.EllipticCurvePrivateKey, common_name: str) -> str:
    """Build and self-sign a CSR for ``common_name``.

    The CN carried here is a *request*, not a guarantee - :func:`sign_csr`
    rebuilds the subject from its own input. It is still set so the CSR is
    self-describing for a human reviewing an enrolment request.

    Returns:
        PEM-encoded CSR.
    """
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.PEM).decode()


# =============================================================================
# CA side - CSR validation and signing
# =============================================================================


def _validate_csr_public_key(
    public_key: CertificatePublicKeyTypes,
) -> Result[None, CsrUnsupportedKeyError]:
    """Reject public keys this CA will not certify.

    Ed25519/Ed448/DSA are refused even though the CA could happily sign them,
    because the credential helper cannot use them to sign a CreateSession
    request - the resulting certificate would be inert.
    """
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        curve = public_key.curve.name
        if curve not in _ALLOWED_EC_CURVES:
            return Err(
                CsrUnsupportedKeyError(
                    key_type=f"EC/{curve}",
                    reason=f"curve not allowed; expected one of {sorted(_ALLOWED_EC_CURVES)}",
                )
            )
        return Ok(None)

    if isinstance(public_key, rsa.RSAPublicKey):
        if public_key.key_size < _MIN_RSA_KEY_SIZE:
            return Err(
                CsrUnsupportedKeyError(
                    key_type=f"RSA/{public_key.key_size}",
                    reason=f"key too small; minimum is {_MIN_RSA_KEY_SIZE} bits",
                )
            )
        return Ok(None)

    return Err(
        CsrUnsupportedKeyError(
            key_type=type(public_key).__name__,
            reason=(
                "IAM Roles Anywhere requires an RSA or ECDSA key; this key type "
                "cannot sign a CreateSession request"
            ),
        )
    )


def parse_and_validate_csr(
    csr_pem: str,
) -> Result[x509.CertificateSigningRequest, SignCsrError]:
    """Parse a PEM CSR and check it is safe to sign.

    Three checks, in order:

    1. It parses as a PEM CSR.
    2. Its self-signature verifies - proof that the requester holds the private
       key for the public key being certified (proof of possession).
    3. Its public key is a type and size we will certify.
    """
    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode())
    except (ValueError, TypeError) as e:
        return Err(CsrParseError(reason=str(e)))

    if not csr.is_signature_valid:
        return Err(CsrInvalidSignatureError())

    match _validate_csr_public_key(csr.public_key()):
        case Err(e):
            return Err(e)

    return Ok(csr)


def sign_csr(
    csr_pem: str,
    ca_cert_pem: str,
    ca_key_pem: str,
    common_name: str,
    validity_days: int = 365,
) -> Result[str, SignCsrError]:
    """Sign a CSR with the CA, issuing a client-auth certificate.

    **The CSR supplies only a public key.** Everything else in the issued
    certificate - subject, validity, extensions - is constructed here from the
    caller's parameters. The CSR's own subject and any requested extensions are
    never copied.

    This matters because from v3 the CSR is generated on the *host*, so its
    contents are attacker-controlled if a host is compromised. A CA that echoed
    a CSR's subject would let one host obtain a certificate naming another.

    Args:
        csr_pem: PEM-encoded CSR from the requester.
        ca_cert_pem: CA certificate, PEM.
        ca_key_pem: CA private key, PEM.
        common_name: CN to certify. Authoritative - overrides the CSR's subject.
        validity_days: Lifetime of the issued certificate.

    Returns:
        Ok with the PEM-encoded certificate, or Err describing why the CSR was
        refused.
    """
    match parse_and_validate_csr(csr_pem):
        case Err(e):
            return Err(e)
        case Ok(csr):
            pass

    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode())
    ca_key = serialization.load_pem_private_key(ca_key_pem.encode(), password=None)

    public_key = csr.public_key()
    now = datetime.now(UTC)

    cert = (
        x509.CertificateBuilder()
        # Subject is rebuilt from our own input - the CSR does not get a say.
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(ca_cert.subject)
        .public_key(public_key)
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
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    return Ok(cert.public_bytes(serialization.Encoding.PEM).decode())


def generate_host_cert(
    hostname: str,
    ca_cert_pem: str,
    ca_key_pem: str,
    validity_days: int = 365,
) -> KeyPair:
    """Generate a host keypair and a certificate for it, signed by the CA.

    Both the key and the certificate are produced on whichever machine calls
    this, which makes it the **v2 flow**. It is retained while the v3 host-side
    enrolment commands are built out, and is scheduled for removal once
    ``host request`` / ``host approve`` replace it. Prefer generating the key in
    a :mod:`~iam_ra_cli.lib.keystore` backend on the host and calling
    :func:`sign_csr`.

    Implemented on top of :func:`sign_csr` so there is exactly one
    certificate-issuing code path.

    Args:
        hostname: Host identifier (becomes certificate CN)
        ca_cert_pem: CA certificate in PEM format
        ca_key_pem: CA private key in PEM format
        validity_days: How long the host cert is valid

    Returns:
        KeyPair with PEM-encoded certificate and private key
    """
    private_key = generate_private_key()
    csr_pem = build_csr(private_key, hostname)

    match sign_csr(
        csr_pem=csr_pem,
        ca_cert_pem=ca_cert_pem,
        ca_key_pem=ca_key_pem,
        common_name=hostname,
        validity_days=validity_days,
    ):
        case Err(e):
            # Unreachable: the CSR was just built here from a fresh P-256 key,
            # so it parses, self-verifies, and uses an allowed curve.
            raise AssertionError(f"self-generated CSR was rejected: {e}")
        case Ok(cert_pem):
            return KeyPair(
                certificate=cert_pem,
                private_key=serialize_private_key(private_key),
            )


def generate_host_keypair_and_csr(hostname: str) -> HostKeyAndCsr:
    """Generate a host private key and CSR for signing by an external CA.

    Use this when the host certificate will be signed by ACM Private CA
    (not locally). The resulting CSR is submitted to PCA's IssueCertificate
    API; the returned private key stays with the caller.

    Args:
        hostname: Host identifier (becomes CSR CN)

    Returns:
        HostKeyAndCsr with PEM-encoded private key and CSR.
    """
    private_key = generate_private_key()
    return HostKeyAndCsr(
        private_key_pem=serialize_private_key(private_key),
        csr_pem=build_csr(private_key, hostname),
    )
