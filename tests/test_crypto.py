"""Tests for lib/crypto.py - Certificate generation and CSR signing."""

import base64
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID

from iam_ra_cli.lib.crypto import (
    KeyPair,
    build_csr,
    generate_ca,
    generate_host_cert,
    generate_host_keypair_and_csr,
    generate_private_key,
    inspect_certificate,
    parse_and_validate_csr,
    sign_csr,
)
from iam_ra_cli.lib.errors import (
    CsrInvalidSignatureError,
    CsrParseError,
    CsrUnsupportedKeyError,
)
from iam_ra_cli.lib.result import Err, Ok


class TestGenerateCA:
    """Tests for CA certificate generation."""

    def test_generates_valid_pem(self) -> None:
        keypair = generate_ca(common_name="Test CA")

        assert keypair.certificate.startswith("-----BEGIN CERTIFICATE-----")
        assert keypair.private_key.startswith("-----BEGIN EC PRIVATE KEY-----")

    def test_ca_is_self_signed(self) -> None:
        keypair = generate_ca(common_name="Test CA")
        cert = x509.load_pem_x509_certificate(keypair.certificate.encode())

        # Subject and issuer should be the same
        assert cert.subject == cert.issuer

    def test_ca_has_correct_cn(self) -> None:
        keypair = generate_ca(common_name="My Custom CA")
        cert = x509.load_pem_x509_certificate(keypair.certificate.encode())

        cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0]
        assert cn.value == "My Custom CA"

    def test_ca_has_basic_constraints(self) -> None:
        keypair = generate_ca()
        cert = x509.load_pem_x509_certificate(keypair.certificate.encode())

        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.critical is True
        assert bc.value.ca is True
        assert bc.value.path_length == 0

    def test_ca_has_key_usage(self) -> None:
        keypair = generate_ca()
        cert = x509.load_pem_x509_certificate(keypair.certificate.encode())

        ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
        assert ku.critical is True
        assert ku.value.digital_signature is True
        assert ku.value.key_cert_sign is True
        assert ku.value.crl_sign is True

    def test_ca_validity_period(self) -> None:
        keypair = generate_ca(validity_years=5)
        cert = x509.load_pem_x509_certificate(keypair.certificate.encode())

        validity_days = (cert.not_valid_after_utc - cert.not_valid_before_utc).days
        # Should be approximately 5 years (1825 days, give or take leap years)
        assert 1820 <= validity_days <= 1830

    def test_ca_key_is_ec_p256(self) -> None:
        keypair = generate_ca()
        key = serialization.load_pem_private_key(keypair.private_key.encode(), password=None)

        # Check it's an EC key (curve check requires cryptography internals)
        assert hasattr(key, "curve")
        assert key.curve.name == "secp256r1"


class TestGenerateHostCert:
    """Tests for host certificate generation."""

    @pytest.fixture
    def ca_keypair(self) -> KeyPair:
        return generate_ca(common_name="Test CA")

    def test_generates_valid_pem(self, ca_keypair: KeyPair) -> None:
        keypair = generate_host_cert(
            hostname="web1",
            ca_cert_pem=ca_keypair.certificate,
            ca_key_pem=ca_keypair.private_key,
        )

        assert keypair.certificate.startswith("-----BEGIN CERTIFICATE-----")
        assert keypair.private_key.startswith("-----BEGIN EC PRIVATE KEY-----")

    def test_host_cert_is_signed_by_ca(self, ca_keypair: KeyPair) -> None:
        keypair = generate_host_cert(
            hostname="web1",
            ca_cert_pem=ca_keypair.certificate,
            ca_key_pem=ca_keypair.private_key,
        )

        host_cert = x509.load_pem_x509_certificate(keypair.certificate.encode())
        ca_cert = x509.load_pem_x509_certificate(ca_keypair.certificate.encode())

        # Issuer of host cert should match subject of CA cert
        assert host_cert.issuer == ca_cert.subject

        # Verify signature (this will raise if invalid)
        ca_cert.public_key().verify(
            host_cert.signature,
            host_cert.tbs_certificate_bytes,
            host_cert.signature_algorithm_parameters,
        )

    def test_host_cert_has_correct_cn(self, ca_keypair: KeyPair) -> None:
        keypair = generate_host_cert(
            hostname="my-hostname",
            ca_cert_pem=ca_keypair.certificate,
            ca_key_pem=ca_keypair.private_key,
        )

        cert = x509.load_pem_x509_certificate(keypair.certificate.encode())
        cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0]
        assert cn.value == "my-hostname"

    def test_host_cert_is_not_ca(self, ca_keypair: KeyPair) -> None:
        keypair = generate_host_cert(
            hostname="web1",
            ca_cert_pem=ca_keypair.certificate,
            ca_key_pem=ca_keypair.private_key,
        )

        cert = x509.load_pem_x509_certificate(keypair.certificate.encode())
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is False

    def test_host_cert_has_client_auth_eku(self, ca_keypair: KeyPair) -> None:
        keypair = generate_host_cert(
            hostname="web1",
            ca_cert_pem=ca_keypair.certificate,
            ca_key_pem=ca_keypair.private_key,
        )

        cert = x509.load_pem_x509_certificate(keypair.certificate.encode())
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        assert ExtendedKeyUsageOID.CLIENT_AUTH in eku.value

    def test_host_cert_validity_period(self, ca_keypair: KeyPair) -> None:
        keypair = generate_host_cert(
            hostname="web1",
            ca_cert_pem=ca_keypair.certificate,
            ca_key_pem=ca_keypair.private_key,
            validity_days=90,
        )

        cert = x509.load_pem_x509_certificate(keypair.certificate.encode())
        validity_days = (cert.not_valid_after_utc - cert.not_valid_before_utc).days
        assert validity_days == 90

    def test_each_host_cert_has_unique_key(self, ca_keypair: KeyPair) -> None:
        """Each host cert should have its own unique private key."""
        keypair1 = generate_host_cert(
            hostname="web1",
            ca_cert_pem=ca_keypair.certificate,
            ca_key_pem=ca_keypair.private_key,
        )
        keypair2 = generate_host_cert(
            hostname="web2",
            ca_cert_pem=ca_keypair.certificate,
            ca_key_pem=ca_keypair.private_key,
        )

        # Keys should be different
        assert keypair1.private_key != keypair2.private_key

    def test_each_host_cert_has_unique_serial(self, ca_keypair: KeyPair) -> None:
        """Each host cert should have its own serial number."""
        keypair1 = generate_host_cert(
            hostname="web1",
            ca_cert_pem=ca_keypair.certificate,
            ca_key_pem=ca_keypair.private_key,
        )
        keypair2 = generate_host_cert(
            hostname="web1",  # Same hostname
            ca_cert_pem=ca_keypair.certificate,
            ca_key_pem=ca_keypair.private_key,
        )

        cert1 = x509.load_pem_x509_certificate(keypair1.certificate.encode())
        cert2 = x509.load_pem_x509_certificate(keypair2.certificate.encode())

        assert cert1.serial_number != cert2.serial_number


class TestGenerateHostKeypairAndCSR:
    """Tests for host keypair and CSR generation (used with ACM PCA)."""

    def test_returns_pem_private_key(self) -> None:
        result = generate_host_keypair_and_csr(hostname="web1")

        assert result.private_key_pem.startswith("-----BEGIN EC PRIVATE KEY-----")

    def test_returns_pem_csr(self) -> None:
        result = generate_host_keypair_and_csr(hostname="web1")

        assert result.csr_pem.startswith("-----BEGIN CERTIFICATE REQUEST-----")

    def test_csr_has_correct_cn(self) -> None:
        result = generate_host_keypair_and_csr(hostname="my-custom-host")

        csr = x509.load_pem_x509_csr(result.csr_pem.encode())
        cn = csr.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0]
        assert cn.value == "my-custom-host"

    def test_csr_has_client_auth_eku(self) -> None:
        result = generate_host_keypair_and_csr(hostname="web1")

        csr = x509.load_pem_x509_csr(result.csr_pem.encode())
        eku = csr.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        assert ExtendedKeyUsageOID.CLIENT_AUTH in eku.value

    def test_csr_signature_is_valid(self) -> None:
        """CSR must be signed by the generated private key (verifies integrity)."""
        result = generate_host_keypair_and_csr(hostname="web1")

        csr = x509.load_pem_x509_csr(result.csr_pem.encode())
        # Raises InvalidSignature if the CSR's signature doesn't match its public key
        assert csr.is_signature_valid

    def test_csr_public_key_matches_private_key(self) -> None:
        """The public key in the CSR must correspond to the returned private key."""
        result = generate_host_keypair_and_csr(hostname="web1")

        csr = x509.load_pem_x509_csr(result.csr_pem.encode())
        private_key = serialization.load_pem_private_key(
            result.private_key_pem.encode(), password=None
        )

        csr_pub_pem = csr.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        priv_pub_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        assert csr_pub_pem == priv_pub_pem

    def test_private_key_is_ec_p256(self) -> None:
        result = generate_host_keypair_and_csr(hostname="web1")

        key = serialization.load_pem_private_key(result.private_key_pem.encode(), password=None)
        assert hasattr(key, "curve")
        assert key.curve.name == "secp256r1"

    def test_each_call_produces_unique_keypair(self) -> None:
        """Repeated calls must generate fresh keypairs - never reuse keys."""
        result1 = generate_host_keypair_and_csr(hostname="web1")
        result2 = generate_host_keypair_and_csr(hostname="web1")  # same hostname

        assert result1.private_key_pem != result2.private_key_pem
        assert result1.csr_pem != result2.csr_pem



class TestSignCsr:
    """Tests for sign_csr - the single certificate-issuing primitive.

    The security-critical property is that a CSR contributes ONLY a public key.
    Everything else in the issued certificate comes from the caller.
    """

    @pytest.fixture
    def ca_keypair(self) -> KeyPair:
        return generate_ca(common_name="Test CA")

    @pytest.fixture
    def csr_pem(self) -> str:
        return build_csr(generate_private_key(), "web01")

    def _sign(self, csr_pem: str, ca: KeyPair, cn: str = "web01", **kw: object) -> str:
        match sign_csr(csr_pem, ca.certificate, ca.private_key, cn, **kw):
            case Ok(pem):
                return pem
            case Err(e):
                pytest.fail(f"expected Ok, got Err({e})")

    def test_issues_pem_certificate(self, csr_pem: str, ca_keypair: KeyPair) -> None:
        cert_pem = self._sign(csr_pem, ca_keypair)

        assert cert_pem.startswith("-----BEGIN CERTIFICATE-----")

    def test_certificate_is_signed_by_ca(self, csr_pem: str, ca_keypair: KeyPair) -> None:
        cert = x509.load_pem_x509_certificate(self._sign(csr_pem, ca_keypair).encode())
        ca_cert = x509.load_pem_x509_certificate(ca_keypair.certificate.encode())

        assert cert.issuer == ca_cert.subject
        # Raises if the signature does not verify.
        ca_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            cert.signature_algorithm_parameters,
        )

    def test_certifies_the_csr_public_key(self, ca_keypair: KeyPair) -> None:
        """The issued cert must bind the requester's key, not a fresh one."""
        requester_key = generate_private_key()
        csr_pem = build_csr(requester_key, "web01")

        cert = x509.load_pem_x509_certificate(self._sign(csr_pem, ca_keypair).encode())

        spki = serialization.PublicFormat.SubjectPublicKeyInfo
        assert cert.public_key().public_bytes(
            serialization.Encoding.DER, spki
        ) == requester_key.public_key().public_bytes(serialization.Encoding.DER, spki)

    def test_subject_comes_from_caller_not_csr(self, ca_keypair: KeyPair) -> None:
        """A host must not be able to name itself something else.

        This is the key defence once CSRs are generated on (possibly
        compromised) hosts: the CA rebuilds the subject from its own input.
        """
        lying_csr = build_csr(generate_private_key(), "admin-box")

        cert = x509.load_pem_x509_certificate(
            self._sign(lying_csr, ca_keypair, cn="web01").encode()
        )

        cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0]
        assert cn.value == "web01"
        assert "admin-box" not in cert.subject.rfc4514_string()

    def test_csr_requested_extensions_are_not_copied(self, ca_keypair: KeyPair) -> None:
        """A CSR must not be able to talk itself into being a CA."""
        key = generate_private_key()
        sneaky_csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "web01")]))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256())
        )
        sneaky_pem = sneaky_csr.public_bytes(serialization.Encoding.PEM).decode()

        cert = x509.load_pem_x509_certificate(self._sign(sneaky_pem, ca_keypair).encode())

        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is False

    def test_issued_cert_has_client_auth_eku(self, csr_pem: str, ca_keypair: KeyPair) -> None:
        cert = x509.load_pem_x509_certificate(self._sign(csr_pem, ca_keypair).encode())

        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        assert ExtendedKeyUsageOID.CLIENT_AUTH in eku.value

    def test_validity_days_honoured(self, csr_pem: str, ca_keypair: KeyPair) -> None:
        cert = x509.load_pem_x509_certificate(
            self._sign(csr_pem, ca_keypair, validity_days=7).encode()
        )

        assert (cert.not_valid_after_utc - cert.not_valid_before_utc).days == 7

    def test_serials_are_unique(self, csr_pem: str, ca_keypair: KeyPair) -> None:
        c1 = x509.load_pem_x509_certificate(self._sign(csr_pem, ca_keypair).encode())
        c2 = x509.load_pem_x509_certificate(self._sign(csr_pem, ca_keypair).encode())

        assert c1.serial_number != c2.serial_number

    def test_rejects_unparseable_csr(self, ca_keypair: KeyPair) -> None:
        match sign_csr("not a csr", ca_keypair.certificate, ca_keypair.private_key, "web01"):
            case Err(e):
                assert isinstance(e, CsrParseError)
            case Ok(_):
                pytest.fail("garbage CSR should be refused")

    def test_rejects_csr_with_broken_signature(self, ca_keypair: KeyPair) -> None:
        """Proof of possession: a tampered CSR must not be signed."""
        csr = x509.load_pem_x509_csr(build_csr(generate_private_key(), "web01").encode())
        der = bytearray(csr.public_bytes(serialization.Encoding.DER))
        # Corrupt bytes near the end, which land in the signature.
        der[-1] ^= 0xFF
        der[-2] ^= 0xFF
        tampered_pem = (
            "-----BEGIN CERTIFICATE REQUEST-----\n"
            + base64.encodebytes(bytes(der)).decode()
            + "-----END CERTIFICATE REQUEST-----\n"
        )

        match sign_csr(tampered_pem, ca_keypair.certificate, ca_keypair.private_key, "web01"):
            case Err(e):
                # Specifically the proof-of-possession check, not a parse failure.
                assert isinstance(e, CsrInvalidSignatureError)
            case Ok(_):
                pytest.fail("CSR with an invalid signature should be refused")

    def test_rejects_weak_rsa_key(self, ca_keypair: KeyPair) -> None:
        weak_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "web01")]))
            .sign(weak_key, hashes.SHA256())
        )
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()

        match sign_csr(csr_pem, ca_keypair.certificate, ca_keypair.private_key, "web01"):
            case Err(e):
                assert isinstance(e, CsrUnsupportedKeyError)
                assert "too small" in e.reason
            case Ok(_):
                pytest.fail("1024-bit RSA should be refused")

    def test_accepts_strong_rsa_key(self, ca_keypair: KeyPair) -> None:
        strong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "web01")]))
            .sign(strong_key, hashes.SHA256())
        )
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()

        assert self._sign(csr_pem, ca_keypair).startswith("-----BEGIN CERTIFICATE-----")

    def test_rejects_ed25519_key(self, ca_keypair: KeyPair) -> None:
        """Ed25519 certs would be inert - the helper cannot sign with them."""
        ed_key = ed25519.Ed25519PrivateKey.generate()
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "web01")]))
            .sign(ed_key, None)
        )
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()

        match sign_csr(csr_pem, ca_keypair.certificate, ca_keypair.private_key, "web01"):
            case Err(e):
                assert isinstance(e, CsrUnsupportedKeyError)
                assert "RSA or ECDSA" in e.reason
            case Ok(_):
                pytest.fail("Ed25519 should be refused")

    def test_rejects_disallowed_ec_curve(self, ca_keypair: KeyPair) -> None:
        weak_key = ec.generate_private_key(ec.SECP192R1())
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "web01")]))
            .sign(weak_key, hashes.SHA256())
        )
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()

        match sign_csr(csr_pem, ca_keypair.certificate, ca_keypair.private_key, "web01"):
            case Err(e):
                assert isinstance(e, CsrUnsupportedKeyError)
                assert "curve not allowed" in e.reason
            case Ok(_):
                pytest.fail("P-192 should be refused")

    @pytest.mark.parametrize("curve", [ec.SECP256R1(), ec.SECP384R1(), ec.SECP521R1()])
    def test_accepts_allowed_ec_curves(self, ca_keypair: KeyPair, curve: object) -> None:
        key = ec.generate_private_key(curve)
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "web01")]))
            .sign(key, hashes.SHA256())
        )
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()

        assert self._sign(csr_pem, ca_keypair).startswith("-----BEGIN CERTIFICATE-----")


class TestParseAndValidateCsr:
    def test_accepts_a_good_csr(self) -> None:
        csr_pem = build_csr(generate_private_key(), "web01")

        match parse_and_validate_csr(csr_pem):
            case Ok(csr):
                cn = csr.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0]
                assert cn.value == "web01"
            case Err(e):
                pytest.fail(f"good CSR rejected: {e}")

    def test_reports_parse_failure_reason(self) -> None:
        match parse_and_validate_csr("garbage"):
            case Err(e):
                assert isinstance(e, CsrParseError)
                assert e.reason
            case Ok(_):
                pytest.fail("garbage should not parse")



class TestInspectCertificate:
    """inspect_certificate extracts what state needs to record about an
    issued certificate without storing the certificate itself."""

    @pytest.fixture
    def ca_keypair(self) -> KeyPair:
        return generate_ca(common_name="Test CA")

    def _cert_with_serial(self, ca: KeyPair, serial: int) -> str:
        """Issue a certificate with an exact serial, so serial formatting can
        be asserted deterministically rather than depending on randomness."""
        ca_cert = x509.load_pem_x509_certificate(ca.certificate.encode())
        ca_key = serialization.load_pem_private_key(ca.private_key.encode(), password=None)
        key = generate_private_key()
        now = datetime.now(UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "web01")]))
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(serial)
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=7))
            .sign(ca_key, hashes.SHA256())
        )
        return cert.public_bytes(serialization.Encoding.PEM).decode()

    def test_extracts_common_name(self, ca_keypair: KeyPair) -> None:
        cert_pem = self._cert_with_serial(ca_keypair, 0x1234)

        match inspect_certificate(cert_pem):
            case Ok(info):
                assert info.subject_common_name == "web01"
            case Err(e):
                pytest.fail(f"unexpected Err({e})")

    def test_serial_is_uppercase_hex(self, ca_keypair: KeyPair) -> None:
        cert_pem = self._cert_with_serial(ca_keypair, 0xABCDEF)

        match inspect_certificate(cert_pem):
            case Ok(info):
                assert info.serial == "ABCDEF"
            case Err(e):
                pytest.fail(f"unexpected Err({e})")

    def test_serial_has_no_leading_zeros(self, ca_keypair: KeyPair) -> None:
        """--cert-selector x509Serial is parsed base-16 and compared against
        Go's big.Int rendering, which omits leading zeros. `openssl x509
        -serial` pads to an even digit count, so the two disagree for serials
        whose top byte is < 0x10. We must match the helper, not openssl.
        """
        cert_pem = self._cert_with_serial(ca_keypair, 0x0B072F63)

        match inspect_certificate(cert_pem):
            case Ok(info):
                assert info.serial == "B072F63"
                assert not info.serial.startswith("0")
            case Err(e):
                pytest.fail(f"unexpected Err({e})")

    def test_validity_is_iso8601(self, ca_keypair: KeyPair) -> None:
        cert_pem = self._cert_with_serial(ca_keypair, 0x01)

        match inspect_certificate(cert_pem):
            case Ok(info):
                # Round-trips through fromisoformat, and is timezone-aware so
                # expiry comparisons cannot silently compare naive to aware.
                parsed = datetime.fromisoformat(info.not_after)
                assert parsed.tzinfo is not None
                assert datetime.fromisoformat(info.not_before) < parsed
            case Err(e):
                pytest.fail(f"unexpected Err({e})")

    def test_reports_expiry_seven_days_out(self, ca_keypair: KeyPair) -> None:
        cert_pem = self._cert_with_serial(ca_keypair, 0x02)

        match inspect_certificate(cert_pem):
            case Ok(info):
                delta = datetime.fromisoformat(info.not_after) - datetime.now(UTC)
                assert 6 <= delta.days <= 7
            case Err(e):
                pytest.fail(f"unexpected Err({e})")

    def test_rejects_garbage(self) -> None:
        match inspect_certificate("not a certificate"):
            case Err(e):
                assert isinstance(e, CsrParseError)
            case Ok(_):
                pytest.fail("garbage should be rejected")

    def test_rejects_a_csr(self) -> None:
        """A CSR is not a certificate - passing one must fail, not half-work."""
        csr_pem = build_csr(generate_private_key(), "web01")

        match inspect_certificate(csr_pem):
            case Err(e):
                assert isinstance(e, CsrParseError)
            case Ok(_):
                pytest.fail("a CSR is not a certificate")

    def test_matches_signed_certificate_from_sign_csr(self, ca_keypair: KeyPair) -> None:
        """The normal path: whatever sign_csr issues must be inspectable."""
        csr_pem = build_csr(generate_private_key(), "web01")
        match sign_csr(csr_pem, ca_keypair.certificate, ca_keypair.private_key, "web01"):
            case Ok(cert_pem):
                pass
            case Err(e):
                pytest.fail(f"sign_csr failed: {e}")

        match inspect_certificate(cert_pem):
            case Ok(info):
                assert info.subject_common_name == "web01"
                assert info.serial
                assert info.not_after
            case Err(e):
                pytest.fail(f"unexpected Err({e})")
