"""Tests for lib/crypto.py - Certificate generation."""

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtendedKeyUsageOID

from iam_ra_cli.lib.crypto import KeyPair, generate_ca, generate_host_cert


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
