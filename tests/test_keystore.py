"""Tests for lib/keystore.py - host key stores."""

import dataclasses
import stat
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from iam_ra_cli.lib import crypto
from iam_ra_cli.lib.errors import (
    KeyAlreadyExistsError,
    KeyNotFoundError,
    KeyStoreOperationError,
)
from iam_ra_cli.lib.keystore import (
    EnrolmentRequest,
    FileCredentialSource,
    FileKeyStore,
    get_keystore,
    make_label,
    validate_label,
)
from iam_ra_cli.lib.result import Err, Ok


@pytest.fixture
def ca() -> crypto.KeyPair:
    return crypto.generate_ca(common_name="Test CA")


@pytest.fixture
def store(tmp_path: Path) -> FileKeyStore:
    return FileKeyStore(root=tmp_path / "keys")


def _unwrap(result):  # noqa: ANN001, ANN202
    """Assert Ok and return the value, so tests fail loudly on Err."""
    match result:
        case Ok(v):
            return v
        case Err(e):
            pytest.fail(f"expected Ok, got Err({e})")


class TestLabels:
    def test_make_label_joins_namespace_and_scope(self) -> None:
        assert make_label("default", "work") == "default-work"

    @pytest.mark.parametrize("label", ["default", "a", "ns-scope", "ns_scope", "ns.scope", "a1"])
    def test_valid_labels_accepted(self, label: str) -> None:
        assert _unwrap(validate_label(label)) == label

    @pytest.mark.parametrize(
        "label",
        [
            "",
            "../escape",
            "with/slash",
            "-leading-dash",
            ".leading-dot",
            "_leading-underscore",
            "has space",
            "has:colon",
            "x" * 64,
        ],
    )
    def test_unsafe_labels_rejected(self, label: str) -> None:
        """Labels become directory names and keychain labels - no traversal."""
        match validate_label(label):
            case Err(e):
                assert isinstance(e, KeyStoreOperationError)
            case Ok(_):
                pytest.fail(f"label {label!r} should have been rejected")


class TestFileKeyStoreGenerate:
    def test_returns_enrolment_request_with_csr(self, store: FileKeyStore) -> None:
        req = _unwrap(store.generate("default-work", "web01"))

        assert isinstance(req, EnrolmentRequest)
        assert req.backend == "files"
        assert req.label == "default-work"
        assert req.csr_pem.startswith("-----BEGIN CERTIFICATE REQUEST-----")

    def test_enrolment_request_carries_no_private_key(self, store: FileKeyStore) -> None:
        """The core invariant: generate() never hands back private material."""
        req = _unwrap(store.generate("default-work", "web01"))

        field_names = {f.name for f in dataclasses.fields(req)}
        assert "private_key" not in field_names
        assert "private_key_pem" not in field_names
        # And nothing in the returned payload smells like a private key.
        for f in dataclasses.fields(req):
            assert "PRIVATE KEY" not in str(getattr(req, f.name))

    def test_csr_cn_is_the_requested_common_name(self, store: FileKeyStore) -> None:
        req = _unwrap(store.generate("default-work", "my-host"))

        csr = x509.load_pem_x509_csr(req.csr_pem.encode())
        cn = csr.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0]
        assert cn.value == "my-host"

    def test_csr_is_self_signed_by_the_stored_key(self, store: FileKeyStore) -> None:
        req = _unwrap(store.generate("default-work", "web01"))
        csr = x509.load_pem_x509_csr(req.csr_pem.encode())

        assert csr.is_signature_valid

        stored = serialization.load_pem_private_key(
            store.key_path("default-work").read_bytes(), password=None
        )
        spki = serialization.PublicFormat.SubjectPublicKeyInfo
        assert csr.public_key().public_bytes(
            serialization.Encoding.DER, spki
        ) == stored.public_key().public_bytes(serialization.Encoding.DER, spki)

    def test_key_written_as_sec1_pem(self, store: FileKeyStore) -> None:
        """SEC1, not PKCS#8 - macOS `security import` rejects bare PKCS#8 EC keys."""
        _unwrap(store.generate("default-work", "web01"))

        assert store.key_path("default-work").read_text().startswith(
            "-----BEGIN EC PRIVATE KEY-----"
        )

    def test_key_file_is_owner_only(self, store: FileKeyStore) -> None:
        _unwrap(store.generate("default-work", "web01"))

        mode = stat.S_IMODE(store.key_path("default-work").stat().st_mode)
        assert mode == 0o600, f"key mode {oct(mode)} is too permissive"

    def test_key_directory_is_owner_only(self, store: FileKeyStore) -> None:
        _unwrap(store.generate("default-work", "web01"))

        mode = stat.S_IMODE(store.key_path("default-work").parent.stat().st_mode)
        assert mode == 0o700, f"key dir mode {oct(mode)} is too permissive"

    def test_refuses_to_overwrite_existing_key(self, store: FileKeyStore) -> None:
        _unwrap(store.generate("default-work", "web01"))
        original = store.key_path("default-work").read_text()

        match store.generate("default-work", "web01"):
            case Err(e):
                assert isinstance(e, KeyAlreadyExistsError)
                assert e.label == "default-work"
            case Ok(_):
                pytest.fail("second generate() should have been refused")

        assert store.key_path("default-work").read_text() == original

    def test_overwrite_flag_replaces_key(self, store: FileKeyStore) -> None:
        _unwrap(store.generate("default-work", "web01"))
        original = store.key_path("default-work").read_text()

        _unwrap(store.generate("default-work", "web01", overwrite=True))

        assert store.key_path("default-work").read_text() != original

    def test_overwrite_discards_stale_certificate(
        self, store: FileKeyStore, ca: crypto.KeyPair
    ) -> None:
        """A cert for the old key must not linger next to a new key."""
        req = _unwrap(store.generate("default-work", "web01"))
        cert = _unwrap(
            crypto.sign_csr(req.csr_pem, ca.certificate, ca.private_key, "web01")
        )
        _unwrap(store.install_certificate("default-work", cert))
        assert store.certificate_path("default-work").exists()

        _unwrap(store.generate("default-work", "web01", overwrite=True))

        assert not store.certificate_path("default-work").exists()

    def test_rejects_unsafe_label(self, store: FileKeyStore) -> None:
        match store.generate("../escape", "web01"):
            case Err(e):
                assert isinstance(e, KeyStoreOperationError)
            case Ok(_):
                pytest.fail("unsafe label should have been rejected")

    def test_each_label_gets_its_own_key(self, store: FileKeyStore) -> None:
        _unwrap(store.generate("ns-a", "web01"))
        _unwrap(store.generate("ns-b", "web01"))

        assert store.key_path("ns-a").read_text() != store.key_path("ns-b").read_text()

    def test_has_key_reflects_state(self, store: FileKeyStore) -> None:
        assert store.has_key("default-work") is False
        _unwrap(store.generate("default-work", "web01"))
        assert store.has_key("default-work") is True


class TestFileKeyStoreInstallCertificate:
    def test_round_trip_generate_sign_install(
        self, store: FileKeyStore, ca: crypto.KeyPair
    ) -> None:
        """The full two-phase enrolment sequence."""
        req = _unwrap(store.generate("default-work", "web01"))
        cert_pem = _unwrap(
            crypto.sign_csr(req.csr_pem, ca.certificate, ca.private_key, "web01")
        )

        source = _unwrap(store.install_certificate("default-work", cert_pem))

        assert isinstance(source, FileCredentialSource)
        assert source.certificate_path == store.certificate_path("default-work")
        assert source.private_key_path == store.key_path("default-work")
        assert source.certificate_path.read_text() == cert_pem

    def test_certificate_is_world_readable(
        self, store: FileKeyStore, ca: crypto.KeyPair
    ) -> None:
        """Certificates are public; restricting them buys nothing."""
        req = _unwrap(store.generate("default-work", "web01"))
        cert_pem = _unwrap(
            crypto.sign_csr(req.csr_pem, ca.certificate, ca.private_key, "web01")
        )
        _unwrap(store.install_certificate("default-work", cert_pem))

        mode = stat.S_IMODE(store.certificate_path("default-work").stat().st_mode)
        assert mode == 0o644

    def test_rejects_certificate_for_a_different_key(
        self, store: FileKeyStore, ca: crypto.KeyPair
    ) -> None:
        """Installing another host's certificate must fail loudly, not later."""
        _unwrap(store.generate("default-work", "web01"))

        # A certificate for an unrelated key.
        other_key = crypto.generate_private_key()
        other_csr = crypto.build_csr(other_key, "web01")
        foreign_cert = _unwrap(
            crypto.sign_csr(other_csr, ca.certificate, ca.private_key, "web01")
        )

        match store.install_certificate("default-work", foreign_cert):
            case Err(e):
                assert isinstance(e, KeyStoreOperationError)
                assert "does not match" in e.reason
            case Ok(_):
                pytest.fail("certificate for a different key should be refused")

        assert not store.certificate_path("default-work").exists()

    def test_rejects_certificate_after_key_regenerated(
        self, store: FileKeyStore, ca: crypto.KeyPair
    ) -> None:
        """A cert issued for a superseded key must not install."""
        req = _unwrap(store.generate("default-work", "web01"))
        stale_cert = _unwrap(
            crypto.sign_csr(req.csr_pem, ca.certificate, ca.private_key, "web01")
        )
        _unwrap(store.generate("default-work", "web01", overwrite=True))

        match store.install_certificate("default-work", stale_cert):
            case Err(e):
                assert isinstance(e, KeyStoreOperationError)
            case Ok(_):
                pytest.fail("stale certificate should be refused")

    def test_rejects_garbage_certificate(self, store: FileKeyStore) -> None:
        _unwrap(store.generate("default-work", "web01"))

        match store.install_certificate("default-work", "not a certificate"):
            case Err(e):
                assert isinstance(e, KeyStoreOperationError)
                assert "not valid PEM" in e.reason
            case Ok(_):
                pytest.fail("garbage certificate should be refused")

    def test_fails_when_no_key_exists(self, store: FileKeyStore, ca: crypto.KeyPair) -> None:
        match store.install_certificate("never-generated", ca.certificate):
            case Err(e):
                assert isinstance(e, KeyNotFoundError)
                assert e.label == "never-generated"
            case Ok(_):
                pytest.fail("install without a key should fail")


class TestFileKeyStoreLocateAndDelete:
    def test_locate_after_full_enrolment(
        self, store: FileKeyStore, ca: crypto.KeyPair
    ) -> None:
        req = _unwrap(store.generate("default-work", "web01"))
        cert_pem = _unwrap(
            crypto.sign_csr(req.csr_pem, ca.certificate, ca.private_key, "web01")
        )
        _unwrap(store.install_certificate("default-work", cert_pem))

        source = _unwrap(store.locate("default-work"))
        assert isinstance(source, FileCredentialSource)

    def test_locate_fails_before_certificate_installed(self, store: FileKeyStore) -> None:
        _unwrap(store.generate("default-work", "web01"))

        match store.locate("default-work"):
            case Err(e):
                assert isinstance(e, KeyNotFoundError)
            case Ok(_):
                pytest.fail("locate should fail until the certificate is installed")

    def test_locate_fails_for_unknown_label(self, store: FileKeyStore) -> None:
        match store.locate("nope"):
            case Err(e):
                assert isinstance(e, KeyNotFoundError)
            case Ok(_):
                pytest.fail("locate should fail for an unknown label")

    def test_delete_removes_key_and_certificate(
        self, store: FileKeyStore, ca: crypto.KeyPair
    ) -> None:
        req = _unwrap(store.generate("default-work", "web01"))
        cert_pem = _unwrap(
            crypto.sign_csr(req.csr_pem, ca.certificate, ca.private_key, "web01")
        )
        _unwrap(store.install_certificate("default-work", cert_pem))

        _unwrap(store.delete("default-work"))

        assert not store.key_path("default-work").exists()
        assert not store.certificate_path("default-work").exists()
        assert store.has_key("default-work") is False

    def test_delete_is_idempotent(self, store: FileKeyStore) -> None:
        _unwrap(store.delete("never-existed"))
        _unwrap(store.delete("never-existed"))

    def test_delete_only_affects_the_named_label(self, store: FileKeyStore) -> None:
        _unwrap(store.generate("ns-a", "web01"))
        _unwrap(store.generate("ns-b", "web01"))

        _unwrap(store.delete("ns-a"))

        assert store.has_key("ns-a") is False
        assert store.has_key("ns-b") is True


class TestDefaultRoot:
    def test_default_root_follows_xdg_state_home(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
        store = FileKeyStore()

        assert store.root == tmp_path / "iam-ra" / "keys"

    def test_generated_key_lands_under_xdg_state_home(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
        store = FileKeyStore()

        _unwrap(store.generate("default-work", "web01"))

        assert (tmp_path / "iam-ra" / "keys" / "default-work" / "key.pem").exists()


class TestGetKeystore:
    def test_returns_file_store(self, tmp_path: Path) -> None:
        store = _unwrap(get_keystore("files", root=tmp_path))
        assert isinstance(store, FileKeyStore)
        assert store.backend == "files"

    def test_unimplemented_backend_fails_explicitly(self) -> None:
        """Must not silently fall back to a less protected store."""
        match get_keystore("macosKeychain"):
            case Err(e):
                assert isinstance(e, KeyStoreOperationError)
                assert "not implemented" in e.reason
            case Ok(_):
                pytest.fail("macosKeychain is not implemented yet; should error")
