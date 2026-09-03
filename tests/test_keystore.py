"""Tests for lib/keystore.py - host key stores."""

import dataclasses
import shutil
import stat
import subprocess
import sys
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
    KeychainCredentialSource,
    KeychainKeyStore,
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

    def test_returns_keychain_store(self) -> None:
        """Constructing it is platform-independent; only its operations require
        macOS, so this is safe to assert on Linux."""
        store = _unwrap(get_keystore("macosKeychain"))
        assert isinstance(store, KeychainKeyStore)
        assert store.backend == "macosKeychain"

    def test_unknown_backend_fails(self) -> None:
        match get_keystore("nonsense"):  # type: ignore[arg-type]
            case Err(e):
                assert isinstance(e, KeyStoreOperationError)
                assert "unknown" in e.reason
            case Ok(_):
                pytest.fail("an unknown backend should error")



# =============================================================================
# macosKeychain backend
# =============================================================================

# These exercise real /usr/bin/security calls, so they only run on macOS.
# python.yaml runs the suite on macos-latest, so they do execute in CI.
darwin_only = pytest.mark.skipif(
    sys.platform != "darwin", reason="macosKeychain requires macOS"
)


def _user_search_list() -> list[str]:
    out = subprocess.run(
        ["/usr/bin/security", "list-keychains", "-d", "user"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return [line.strip().strip('"') for line in out.splitlines() if line.strip()]


@pytest.fixture
def keychain_store(tmp_path: Path):
    """A KeychainKeyStore backed by a throwaway keychain.

    Two things are deliberate:

    * An explicit password, so the test never reads or writes the developer's
      (or the CI runner's) login keychain.
    * The keychain search list is captured and restored. It is global user
      state, and clobbering it breaks every keychain client on the machine.
      Restoration passes the paths as separate argv entries - joining them into
      one string produces a single bogus entry.
    """
    if sys.platform != "darwin":
        pytest.skip("macosKeychain requires macOS")

    original = _user_search_list()
    keychain_path = tmp_path / "iam-ra-test.keychain"
    store = KeychainKeyStore(
        keychain_path=keychain_path,
        password="test-keychain-pass",
        index_path=tmp_path / "index.json",
    )
    try:
        yield store
    finally:
        subprocess.run(
            ["/usr/bin/security", "delete-keychain", str(keychain_path)],
            capture_output=True,
            check=False,
        )
        if original:
            subprocess.run(
                ["/usr/bin/security", "list-keychains", "-d", "user", "-s", *original],
                capture_output=True,
                check=False,
            )


def _sign(ca_kp: crypto.KeyPair, csr_pem: str, cn: str) -> str:
    return _unwrap(crypto.sign_csr(csr_pem, ca_kp.certificate, ca_kp.private_key, cn))


class TestKeychainKeyStorePlatformGuard:
    def test_construction_works_anywhere(self, tmp_path: Path) -> None:
        """Only the operations need macOS, so importing and constructing must
        not explode on Linux - otherwise the CLI could not even offer the
        option."""
        store = KeychainKeyStore(keychain_path=tmp_path / "k.keychain", password="x")
        assert store.backend == "macosKeychain"

    @pytest.mark.skipif(sys.platform == "darwin", reason="tests the non-macOS path")
    def test_generate_refuses_on_non_macos(self, tmp_path: Path) -> None:
        store = KeychainKeyStore(
            keychain_path=tmp_path / "k.keychain",
            password="x",
            index_path=tmp_path / "i.json",
        )

        match store.generate("test-default", "web01"):
            case Err(e):
                assert isinstance(e, KeyStoreOperationError)
                assert "requires macOS" in e.reason
            case Ok(_):
                pytest.fail("keychain generate should refuse off macOS")


@darwin_only
class TestKeychainKeyStore:
    def test_generate_returns_csr_and_no_private_key(self, keychain_store) -> None:
        req = _unwrap(keychain_store.generate("test-default", "web01"))

        assert req.backend == "macosKeychain"
        assert req.csr_pem.startswith("-----BEGIN CERTIFICATE REQUEST-----")
        for f in dataclasses.fields(req):
            assert "PRIVATE KEY" not in str(getattr(req, f.name))

    def test_generate_adds_the_keychain_to_the_search_list(self, keychain_store) -> None:
        """The credential helper only searches keychains on the search list, so
        an identity in an unlisted keychain is invisible to it."""
        _unwrap(keychain_store.generate("test-default", "web01"))

        names = [Path(p).name.removesuffix("-db") for p in _user_search_list()]
        assert keychain_store.keychain_path.name in names

    def test_generate_preserves_existing_search_list_entries(self, keychain_store) -> None:
        """Replacing rather than extending the list would unhook the login
        keychain and break unrelated software."""
        before = {Path(p).name for p in _user_search_list()}

        _unwrap(keychain_store.generate("test-default", "web01"))

        after = {Path(p).name for p in _user_search_list()}
        assert before <= after

    def test_has_key_tracks_state(self, keychain_store) -> None:
        assert keychain_store.has_key("test-default") is False
        _unwrap(keychain_store.generate("test-default", "web01"))
        assert keychain_store.has_key("test-default") is True

    def test_refuses_to_clobber_without_overwrite(self, keychain_store) -> None:
        _unwrap(keychain_store.generate("test-default", "web01"))

        match keychain_store.generate("test-default", "web01"):
            case Err(e):
                assert isinstance(e, KeyAlreadyExistsError)
            case Ok(_):
                pytest.fail("second generate should be refused")

    def test_overwrite_produces_a_different_key(self, keychain_store) -> None:
        first = _unwrap(keychain_store.generate("test-default", "web01"))
        second = _unwrap(keychain_store.generate("test-default", "web01", overwrite=True))

        assert first.csr_pem != second.csr_pem

    def test_locate_fails_before_the_certificate_is_installed(self, keychain_store) -> None:
        """A bare key is not yet an identity, so nothing can use it."""
        _unwrap(keychain_store.generate("test-default", "web01"))

        match keychain_store.locate("test-default"):
            case Err(e):
                assert isinstance(e, KeyNotFoundError)
            case Ok(_):
                pytest.fail("locate should fail until the certificate is installed")

    def test_full_enrolment_yields_a_keychain_credential_source(
        self, keychain_store, ca: crypto.KeyPair
    ) -> None:
        req = _unwrap(keychain_store.generate("test-default", "web01"))
        cert = _sign(ca, req.csr_pem, "web01")

        source = _unwrap(keychain_store.install_certificate("test-default", cert))

        assert isinstance(source, KeychainCredentialSource)
        assert source.subject_common_name == "web01"
        assert source.keychain_path == keychain_store.keychain_path

    def test_locate_works_after_installing_the_certificate(
        self, keychain_store, ca: crypto.KeyPair
    ) -> None:
        req = _unwrap(keychain_store.generate("test-default", "web01"))
        _unwrap(
            keychain_store.install_certificate("test-default", _sign(ca, req.csr_pem, "web01"))
        )

        source = _unwrap(keychain_store.locate("test-default"))
        assert isinstance(source, KeychainCredentialSource)

    def test_rejects_a_certificate_for_a_different_key(
        self, keychain_store, ca: crypto.KeyPair
    ) -> None:
        """The keychain cannot tell us whether a certificate matches the key it
        holds, so the fingerprint recorded at generate time is checked instead."""
        _unwrap(keychain_store.generate("test-default", "web01"))

        foreign_csr = crypto.build_csr(crypto.generate_private_key(), "web01")
        foreign_cert = _sign(ca, foreign_csr, "web01")

        match keychain_store.install_certificate("test-default", foreign_cert):
            case Err(e):
                assert isinstance(e, KeyStoreOperationError)
                assert "does not match" in e.reason
            case Ok(_):
                pytest.fail("a certificate for a different key must be refused")

    def test_rejects_a_stale_certificate_after_overwrite(
        self, keychain_store, ca: crypto.KeyPair
    ) -> None:
        req = _unwrap(keychain_store.generate("test-default", "web01"))
        stale = _sign(ca, req.csr_pem, "web01")
        _unwrap(keychain_store.generate("test-default", "web01", overwrite=True))

        match keychain_store.install_certificate("test-default", stale):
            case Err(e):
                assert isinstance(e, KeyStoreOperationError)
            case Ok(_):
                pytest.fail("a certificate for the superseded key must be refused")

    def test_rejects_garbage_certificate(self, keychain_store) -> None:
        _unwrap(keychain_store.generate("test-default", "web01"))

        match keychain_store.install_certificate("test-default", "not a certificate"):
            case Err(e):
                assert isinstance(e, KeyStoreOperationError)
                assert "not valid PEM" in e.reason
            case Ok(_):
                pytest.fail("garbage must be refused")

    def test_install_without_generate_fails(self, keychain_store, ca: crypto.KeyPair) -> None:
        match keychain_store.install_certificate("never-generated", ca.certificate):
            case Err(e):
                assert isinstance(e, KeyNotFoundError)
            case Ok(_):
                pytest.fail("install without a key must fail")

    def test_private_key_is_non_extractable(self, keychain_store, ca: crypto.KeyPair) -> None:
        """This is the entire security benefit of this backend over `files`: an
        attacker running as the user can use the key but cannot copy it off the
        machine."""
        req = _unwrap(keychain_store.generate("test-default", "web01"))
        _unwrap(
            keychain_store.install_certificate("test-default", _sign(ca, req.csr_pem, "web01"))
        )

        out = Path(str(keychain_store.keychain_path) + ".exported.p8")
        result = subprocess.run(
            [
                "/usr/bin/security",
                "export",
                "-k",
                str(keychain_store.keychain_path),
                "-t",
                "privKeys",
                "-f",
                "pkcs8",
                "-P",
                "",
                "-o",
                str(out),
            ],
            capture_output=True,
            text=True,
            check=False,
        )

        exported = out.exists() and out.stat().st_size > 0
        out.unlink(missing_ok=True)
        assert not exported, "private key was exported; -x is not being applied"
        assert result.returncode != 0

    def test_two_hosts_share_one_keychain(self, keychain_store, ca: crypto.KeyPair) -> None:
        """One keychain per machine, addressed per host by certificate subject."""
        a = _unwrap(keychain_store.generate("ns-a", "host-a"))
        b = _unwrap(keychain_store.generate("ns-b", "host-b"))
        _unwrap(keychain_store.install_certificate("ns-a", _sign(ca, a.csr_pem, "host-a")))
        _unwrap(keychain_store.install_certificate("ns-b", _sign(ca, b.csr_pem, "host-b")))

        src_a = _unwrap(keychain_store.locate("ns-a"))
        src_b = _unwrap(keychain_store.locate("ns-b"))
        assert isinstance(src_a, KeychainCredentialSource)
        assert isinstance(src_b, KeychainCredentialSource)
        assert src_a.subject_common_name == "host-a"
        assert src_b.subject_common_name == "host-b"

    def test_delete_removes_only_the_named_host(
        self, keychain_store, ca: crypto.KeyPair
    ) -> None:
        a = _unwrap(keychain_store.generate("ns-a", "host-a"))
        b = _unwrap(keychain_store.generate("ns-b", "host-b"))
        _unwrap(keychain_store.install_certificate("ns-a", _sign(ca, a.csr_pem, "host-a")))
        _unwrap(keychain_store.install_certificate("ns-b", _sign(ca, b.csr_pem, "host-b")))

        _unwrap(keychain_store.delete("ns-a"))

        assert keychain_store.has_key("ns-a") is False
        assert keychain_store.has_key("ns-b") is True
        _unwrap(keychain_store.locate("ns-b"))

    def test_delete_is_idempotent(self, keychain_store) -> None:
        _unwrap(keychain_store.delete("never-existed"))
        _unwrap(keychain_store.delete("never-existed"))

    def test_rejects_unsafe_label(self, keychain_store) -> None:
        match keychain_store.generate("../escape", "web01"):
            case Err(e):
                assert isinstance(e, KeyStoreOperationError)
            case Ok(_):
                pytest.fail("unsafe label must be refused")

    def test_credential_helper_can_select_and_sign(
        self, keychain_store, ca: crypto.KeyPair
    ) -> None:
        """The end-to-end contract: what the Nix module emits as
        --cert-selector must actually work.

        Skipped when aws_signing_helper is unavailable, since it comes from the
        Nix dev shell rather than pip.
        """
        helper = shutil.which("aws_signing_helper")
        if helper is None:
            pytest.skip("aws_signing_helper not on PATH")

        req = _unwrap(keychain_store.generate("test-default", "web01"))
        source = _unwrap(
            keychain_store.install_certificate("test-default", _sign(ca, req.csr_pem, "web01"))
        )
        assert isinstance(source, KeychainCredentialSource)

        result = subprocess.run(
            [
                helper,
                "sign-string",
                "--cert-selector",
                f"Key=x509Subject,Value=CN={source.subject_common_name}",
                "--format",
                "text",
            ],
            input="test",
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

        combined = (result.stdout + result.stderr).lower()
        # The helper exits 0 even when nothing matched, so the exit code alone
        # is not a usable signal - the output has to be parsed.
        assert "no matching identities" not in combined, combined
        assert result.stdout.strip(), f"no signature produced: {combined}"
