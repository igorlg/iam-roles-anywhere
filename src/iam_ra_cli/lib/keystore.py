"""Key stores - where a host's private key is generated and kept.

From v3 the host private key is generated **on the host** and never leaves it.
A ``KeyStore`` is the abstraction over "where that key lives and how
``aws_signing_helper`` is told to reach it".

The central invariant is expressed in the types: :meth:`KeyStore.generate`
returns an :class:`EnrolmentRequest`, which carries a CSR and **no private key
field**. There is no API on this protocol that hands a private key back to the
caller. Backends may hold the key in process memory transiently while creating
it, but it is never returned, logged, or serialised anywhere but the store.

Two-phase enrolment
-------------------
Backends must support the key existing *before* its certificate does::

    generate(label)              -> EnrolmentRequest (CSR)   # on the host
    ...CSR goes to the admin, comes back as a certificate...
    install_certificate(label, pem) -> CredentialSource       # on the host

Both artefacts in transit are public, so they need no confidential channel.
This ordering is verified for macOS Keychain: a bare key imported first does
form a usable identity once the matching certificate is imported later.

Backends
--------
``files``          portable, no platform dependencies, used by CI.
``macosKeychain``  non-extractable key in a dedicated keychain. macOS only -
                   the credential helper's certificate-store support is a stub
                   that errors at runtime on Linux.
"""

import hashlib
import json
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar, Literal, Protocol

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from iam_ra_cli.lib import crypto
from iam_ra_cli.lib.errors import (
    KeyAlreadyExistsError,
    KeyNotFoundError,
    KeyStoreOperationError,
)
from iam_ra_cli.lib.result import Err, Ok, Result
from iam_ra_cli.lib.storage.file import PRIVATE_KEY_DIR_MODE, write_private_key

type KeyStoreBackend = Literal["files", "macosKeychain"]

type KeyStoreError = KeyAlreadyExistsError | KeyNotFoundError | KeyStoreOperationError

# A label names one key within a store. Restricted to a single safe path
# component so it can be used directly as a directory name and as a keychain
# item label without escaping or traversal concerns.
_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")

# Private-key file and directory modes live in storage.file, alongside the
# writer that enforces them, so there is one definition rather than two.
_KEY_DIR_MODE = PRIVATE_KEY_DIR_MODE
# The certificate is public material; normal permissions are correct.
_CERT_FILE_MODE = 0o644


def make_label(namespace: str, scope: str) -> str:
    """Compose a store label for a namespace/scope pair.

    Kept in one place so the on-disk layout and keychain item labels agree.
    """
    return f"{namespace}-{scope}"


def validate_label(label: str) -> Result[str, KeyStoreOperationError]:
    """Reject labels that are unsafe as a path component or keychain label."""
    if not _LABEL_RE.match(label):
        return Err(
            KeyStoreOperationError(
                backend="-",
                operation="validate_label",
                reason=(
                    f"invalid label {label!r}: must be 1-63 chars of "
                    "[A-Za-z0-9_.-] and start alphanumeric"
                ),
            )
        )
    return Ok(label)


# =============================================================================
# Credential sources - how aws_signing_helper is pointed at the key
# =============================================================================


@dataclass(frozen=True, slots=True)
class FileCredentialSource:
    """Certificate and key as filesystem paths.

    Consumed as ``--certificate <path> --private-key <path>``.
    """

    certificate_path: Path
    private_key_path: Path


@dataclass(frozen=True, slots=True)
class KeychainCredentialSource:
    """An identity in a macOS keychain, selected by certificate subject.

    Consumed as ``--cert-selector``, which is **mutually exclusive** with
    ``--certificate`` and ``--private-key`` in ``aws_signing_helper``. That
    exclusivity is why credential sources are a tagged union rather than one
    struct with optional fields.
    """

    subject_common_name: str
    keychain_path: Path


type CredentialSource = FileCredentialSource | KeychainCredentialSource


@dataclass(frozen=True, slots=True)
class EnrolmentRequest:
    """Public output of key generation.

    Deliberately carries no private key. The key stays in the store; this is
    everything that may safely leave the host.
    """

    label: str
    backend: str
    csr_pem: str


# =============================================================================
# Protocol
# =============================================================================


class KeyStore(Protocol):
    """Where a host private key is generated and kept.

    Implementations must never return private key material.
    """

    backend: ClassVar[KeyStoreBackend]

    def generate(
        self, label: str, common_name: str, *, overwrite: bool = False
    ) -> Result[EnrolmentRequest, KeyStoreError]:
        """Create a key in the store and return a CSR for it."""
        ...

    def install_certificate(
        self, label: str, certificate_pem: str
    ) -> Result[CredentialSource, KeyStoreError]:
        """Attach a signed certificate to the stored key."""
        ...

    def locate(self, label: str) -> Result[CredentialSource, KeyStoreError]:
        """Describe how to reach an already-enrolled key and certificate."""
        ...

    def has_key(self, label: str) -> bool:
        """True if a key exists for this label."""
        ...

    def delete(self, label: str) -> Result[None, KeyStoreError]:
        """Remove the key and certificate for this label."""
        ...


# =============================================================================
# files backend
# =============================================================================


class FileKeyStore:
    """Keys and certificates as files under a root directory.

    Layout, one directory per label::

        <root>/<label>/key.pem     0600, SEC1 EC private key
        <root>/<label>/cert.pem    0644, PEM certificate

    The key is written by ``storage.file.write_private_key``: a 0600 temp file
    renamed into place, so it is never briefly readable by others - unlike
    write-then-``chmod``.

    Unlike the ``macosKeychain`` backend the key here is extractable by anyone
    who can read the file. The security gain over v2 is narrower but still real:
    the key is never transmitted and never escrowed in AWS.
    """

    backend: ClassVar[KeyStoreBackend] = "files"

    def __init__(self, root: Path | None = None) -> None:
        self._root = root if root is not None else _default_file_root()

    @property
    def root(self) -> Path:
        return self._root

    def _dir(self, label: str) -> Path:
        return self._root / label

    def key_path(self, label: str) -> Path:
        return self._dir(label) / "key.pem"

    def certificate_path(self, label: str) -> Path:
        return self._dir(label) / "cert.pem"

    def has_key(self, label: str) -> bool:
        return self.key_path(label).exists()

    def generate(
        self, label: str, common_name: str, *, overwrite: bool = False
    ) -> Result[EnrolmentRequest, KeyStoreError]:
        match validate_label(label):
            case Err(e):
                return Err(e)

        key_path = self.key_path(label)
        if key_path.exists() and not overwrite:
            return Err(
                KeyAlreadyExistsError(
                    backend=self.backend,
                    label=label,
                    location=str(key_path),
                )
            )

        private_key = crypto.generate_private_key()
        csr_pem = crypto.build_csr(private_key, common_name)
        key_pem = crypto.serialize_private_key(private_key)

        try:
            write_private_key(key_path, key_pem)
        except OSError as e:
            return Err(
                KeyStoreOperationError(backend=self.backend, operation="generate", reason=str(e))
            )

        # Stale certificate from a previous enrolment would not match the new
        # key, so drop it rather than leave an inconsistent pair on disk.
        cert_path = self.certificate_path(label)
        if cert_path.exists():
            try:
                cert_path.unlink()
            except OSError as e:
                return Err(
                    KeyStoreOperationError(
                        backend=self.backend,
                        operation="generate",
                        reason=f"could not remove stale certificate {cert_path}: {e}",
                    )
                )

        return Ok(EnrolmentRequest(label=label, backend=self.backend, csr_pem=csr_pem))

    def install_certificate(
        self, label: str, certificate_pem: str
    ) -> Result[CredentialSource, KeyStoreError]:
        match validate_label(label):
            case Err(e):
                return Err(e)

        key_path = self.key_path(label)
        if not key_path.exists():
            return Err(KeyNotFoundError(backend=self.backend, label=label, location=str(key_path)))

        match _check_certificate_matches_key(certificate_pem, key_path.read_text()):
            case Err(reason):
                return Err(
                    KeyStoreOperationError(
                        backend=self.backend, operation="install_certificate", reason=reason
                    )
                )

        cert_path = self.certificate_path(label)
        try:
            cert_path.write_text(certificate_pem)
            cert_path.chmod(_CERT_FILE_MODE)
        except OSError as e:
            return Err(
                KeyStoreOperationError(
                    backend=self.backend, operation="install_certificate", reason=str(e)
                )
            )

        return Ok(FileCredentialSource(certificate_path=cert_path, private_key_path=key_path))

    def locate(self, label: str) -> Result[CredentialSource, KeyStoreError]:
        key_path = self.key_path(label)
        cert_path = self.certificate_path(label)
        if not key_path.exists():
            return Err(KeyNotFoundError(backend=self.backend, label=label, location=str(key_path)))
        if not cert_path.exists():
            return Err(KeyNotFoundError(backend=self.backend, label=label, location=str(cert_path)))
        return Ok(FileCredentialSource(certificate_path=cert_path, private_key_path=key_path))

    def delete(self, label: str) -> Result[None, KeyStoreError]:
        match validate_label(label):
            case Err(e):
                return Err(e)

        target = self._dir(label)
        if not target.exists():
            return Ok(None)  # idempotent
        try:
            shutil.rmtree(target)
        except OSError as e:
            return Err(
                KeyStoreOperationError(backend=self.backend, operation="delete", reason=str(e))
            )
        return Ok(None)


def _default_file_root() -> Path:
    """Default root for the files backend.

    Imported lazily-ish (module-level function rather than a constant) so tests
    that monkeypatch ``XDG_STATE_HOME`` are honoured at call time.
    """
    from iam_ra_cli.lib import paths

    return paths.state_dir() / "keys"


def _check_certificate_matches_key(certificate_pem: str, private_key_pem: str) -> Result[None, str]:
    """Verify a certificate certifies the public key of the stored private key.

    Guards against installing another host's certificate, or a certificate
    issued against a key that has since been regenerated. Without this, the
    mismatch would only surface later as an opaque signing failure inside
    ``aws_signing_helper``.
    """
    try:
        cert = x509.load_pem_x509_certificate(certificate_pem.encode())
    except (ValueError, TypeError) as e:
        return Err(f"certificate is not valid PEM: {e}")

    try:
        private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    except (ValueError, TypeError) as e:
        return Err(f"stored private key could not be loaded: {e}")

    spki = serialization.PublicFormat.SubjectPublicKeyInfo
    cert_pub = cert.public_key().public_bytes(serialization.Encoding.DER, spki)
    key_pub = private_key.public_key().public_bytes(serialization.Encoding.DER, spki)

    if cert_pub != key_pub:
        return Err(
            "certificate public key does not match the stored private key "
            "(wrong certificate, or the key was regenerated after the CSR was issued)"
        )
    return Ok(None)


# =============================================================================
# macosKeychain backend
# =============================================================================

# Where the dedicated keychain's own password is kept, as a generic password in
# the user's login keychain (which macOS unlocks at login).
_LOGIN_ITEM_SERVICE = "iam-ra"
_LOGIN_ITEM_ACCOUNT = "keychain-password"

_SECURITY = "/usr/bin/security"


def _public_key_fingerprint(public_key: object) -> str:
    """SHA-256 of the DER SubjectPublicKeyInfo, hex.

    Used to tie a keychain entry to the key we generated for it, since a bare
    key in a keychain carries no label we can set on import.
    """
    der = public_key.public_bytes(  # type: ignore[attr-defined]
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


@dataclass(frozen=True, slots=True)
class _IndexEntry:
    """Public bookkeeping for one keychain-held key."""

    common_name: str
    public_key_sha256: str


class KeychainKeyStore:
    """Private keys in a dedicated macOS keychain, non-extractable.

    Why this is stronger than the ``files`` backend: the key is imported with
    ``security import -x``, so the Security framework refuses to export it. An
    attacker running as the user can *use* the key (as they could by running
    ``aws`` anyway) but cannot copy it off the machine for offline or later use.
    That is the actual security gain; see the notes on the ACL below.

    Deliberately NOT using ``-T <binary>`` to restrict which program may use the
    key. A spike established that the nix-built ``aws_signing_helper`` is ad-hoc
    signed with no TeamIdentifier, so macOS identifies it by CDHash alone; any
    rebuild changes the hash and invalidates the ACL, turning every ``aws``
    command into an interactive prompt. The ACL also buys very little, because
    any process running as the user can simply execute the authorised binary. So
    the key is imported ``-A`` (any application) and the protection relied upon
    is non-extractability.

    Addressing: an identity in a keychain is selected by its **certificate
    subject**, which is the hostname - that is what ``--cert-selector`` matches.
    The KeyStore protocol addresses keys by *label* (namespace-scope). A small
    JSON index bridges the two. It holds only public data: the common name and
    the key's public-key fingerprint.

    Layout, all under one keychain so a machine with several identities does not
    accumulate keychains::

        <keychain_path>                 e.g. ~/Library/Keychains/iam-ra.keychain
        <state_dir>/keychain-index.json label -> {common_name, public_key_sha256}
    """

    backend: ClassVar[KeyStoreBackend] = "macosKeychain"

    def __init__(
        self,
        keychain_path: Path | None = None,
        password: str | None = None,
        index_path: Path | None = None,
    ) -> None:
        from iam_ra_cli.lib import paths

        self._keychain_path = (
            keychain_path
            if keychain_path is not None
            else Path.home() / "Library" / "Keychains" / "iam-ra.keychain"
        )
        self._explicit_password = password
        self._index_path = (
            index_path if index_path is not None else paths.state_dir() / "keychain-index.json"
        )

    @property
    def keychain_path(self) -> Path:
        return self._keychain_path

    # ---------------- index ----------------

    def _read_index(self) -> dict[str, _IndexEntry]:
        if not self._index_path.exists():
            return {}
        try:
            raw = json.loads(self._index_path.read_text())
        except (OSError, json.JSONDecodeError):
            return {}
        return {
            label: _IndexEntry(
                common_name=entry["common_name"],
                public_key_sha256=entry["public_key_sha256"],
            )
            for label, entry in raw.items()
            if isinstance(entry, dict) and "common_name" in entry and "public_key_sha256" in entry
        }

    def _write_index(self, index: dict[str, _IndexEntry]) -> None:
        self._index_path.parent.mkdir(parents=True, exist_ok=True, mode=_KEY_DIR_MODE)
        payload = {
            label: {
                "common_name": entry.common_name,
                "public_key_sha256": entry.public_key_sha256,
            }
            for label, entry in index.items()
        }
        self._index_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")

    # ---------------- security(1) plumbing ----------------

    def _run(self, args: list[str], operation: str) -> Result[str, KeyStoreOperationError]:
        try:
            proc = subprocess.run(  # noqa: S603
                [_SECURITY, *args],
                capture_output=True,
                text=True,
                check=False,
            )
        except OSError as e:
            return Err(
                KeyStoreOperationError(backend=self.backend, operation=operation, reason=str(e))
            )
        if proc.returncode != 0:
            return Err(
                KeyStoreOperationError(
                    backend=self.backend,
                    operation=operation,
                    reason=(proc.stderr or proc.stdout).strip()
                    or f"security exited {proc.returncode}",
                )
            )
        return Ok(proc.stdout)

    def _check_platform(self) -> Result[None, KeyStoreOperationError]:
        if sys.platform != "darwin":
            return Err(
                KeyStoreOperationError(
                    backend=self.backend,
                    operation="platform_check",
                    reason=(
                        "the macosKeychain key store requires macOS. Note the "
                        "credential helper has no certificate-store support on "
                        "Linux either, so use the 'files' key store there."
                    ),
                )
            )
        return Ok(None)

    def _resolve_password(self) -> Result[str, KeyStoreOperationError]:
        """Find or create the dedicated keychain's password.

        Order: an explicitly supplied password (tests, automation), then a
        generic password in the login keychain, then generate one and store it
        there. Keeping it in the login keychain means it is protected by the
        user's login password and FileVault rather than sitting in a file.

        Caveat: ``security`` takes passwords on argv, so it is briefly visible
        to other processes of the same user via ps. That is an acceptable
        trade-off here - a process able to read argv can also read the unlocked
        login keychain - but it is why this is not treated as a strong secret.
        """
        if self._explicit_password is not None:
            return Ok(self._explicit_password)

        found = self._run(
            [
                "find-generic-password",
                "-s",
                _LOGIN_ITEM_SERVICE,
                "-a",
                _LOGIN_ITEM_ACCOUNT,
                "-w",
            ],
            "find_keychain_password",
        )
        match found:
            case Ok(out) if out.strip():
                return Ok(out.strip())

        password = secrets.token_urlsafe(32)
        match self._run(
            [
                "add-generic-password",
                "-s",
                _LOGIN_ITEM_SERVICE,
                "-a",
                _LOGIN_ITEM_ACCOUNT,
                "-w",
                password,
                "-U",
            ],
            "store_keychain_password",
        ):
            case Err(e):
                return Err(e)
        return Ok(password)

    def _ensure_keychain(self) -> Result[str, KeyStoreOperationError]:
        """Create (if needed), unlock, and search-list the dedicated keychain.

        Returns the keychain password so callers can reuse it.
        """
        match self._check_platform():
            case Err(e):
                return Err(e)

        match self._resolve_password():
            case Err(e):
                return Err(e)
            case Ok(password):
                pass

        if not self._keychain_path.exists():
            self._keychain_path.parent.mkdir(parents=True, exist_ok=True)
            match self._run(
                ["create-keychain", "-p", password, str(self._keychain_path)],
                "create_keychain",
            ):
                case Err(e):
                    return Err(e)

        match self._run(
            ["unlock-keychain", "-p", password, str(self._keychain_path)],
            "unlock_keychain",
        ):
            case Err(e):
                return Err(e)

        # Without this the keychain re-locks after ~5 minutes, which would break
        # credential fetches (and `serve` mode) some time after enrolment.
        match self._run(["set-keychain-settings", str(self._keychain_path)], "keychain_settings"):
            case Err(e):
                return Err(e)

        match self._add_to_search_list():
            case Err(e):
                return Err(e)

        return Ok(password)

    def _add_to_search_list(self) -> Result[None, KeyStoreOperationError]:
        """Put our keychain on the user's search list, preserving what is there.

        The credential helper only searches keychains on the search list. The
        list is global user state, so it must be read and extended - never
        replaced, which would silently drop the login keychain.
        """
        match self._run(["list-keychains", "-d", "user"], "list_keychains"):
            case Err(e):
                return Err(e)
            case Ok(out):
                pass

        existing = [line.strip().strip('"') for line in out.splitlines() if line.strip()]
        target = str(self._keychain_path)

        # Compare resolved paths: `security` reports the -db suffixed real file.
        def same(a: str, b: str) -> bool:
            return Path(a).name.removesuffix("-db") == Path(b).name.removesuffix("-db")

        if any(same(entry, target) for entry in existing):
            return Ok(None)

        match self._run(
            ["list-keychains", "-d", "user", "-s", target, *existing], "set_search_list"
        ):
            case Err(e):
                return Err(e)
        return Ok(None)

    # ---------------- KeyStore protocol ----------------

    def has_key(self, label: str) -> bool:
        return label in self._read_index()

    def generate(
        self, label: str, common_name: str, *, overwrite: bool = False
    ) -> Result[EnrolmentRequest, KeyStoreError]:
        match validate_label(label):
            case Err(e):
                return Err(e)

        index = self._read_index()
        if label in index and not overwrite:
            return Err(
                KeyAlreadyExistsError(
                    backend=self.backend,
                    label=label,
                    location=f"{self._keychain_path} (CN={index[label].common_name})",
                )
            )

        match self._ensure_keychain():
            case Err(e):
                return Err(e)

        # Replacing: drop the old identity so the selector cannot match two
        # certificates with the same CN, which the helper treats as an error.
        if label in index:
            self._delete_identity(index[label].common_name)

        private_key = crypto.generate_private_key()
        csr_pem = crypto.build_csr(private_key, common_name)
        fingerprint = _public_key_fingerprint(private_key.public_key())

        # The key must transit a file to be imported, since `security import`
        # reads a path. It is written into a private temporary directory, with
        # 0600, and unlinked immediately - the keychain is its permanent home.
        #
        # SEC1, not PKCS#8: `security import` rejects a bare PKCS#8 EC key.
        key_pem = crypto.serialize_private_key(private_key)
        tmpdir = tempfile.mkdtemp(prefix="iam-ra-enrol-")
        try:
            key_file = Path(tmpdir) / "key.pem"
            write_private_key(key_file, key_pem)

            # -A: any application may use it. -x: non-extractable. See the class
            # docstring for why -T is deliberately not used.
            match self._run(
                [
                    "import",
                    str(key_file),
                    "-k",
                    str(self._keychain_path),
                    "-P",
                    "",
                    "-A",
                    "-x",
                ],
                "import_private_key",
            ):
                case Err(e):
                    return Err(e)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

        index[label] = _IndexEntry(common_name=common_name, public_key_sha256=fingerprint)
        try:
            self._write_index(index)
        except OSError as e:
            return Err(
                KeyStoreOperationError(backend=self.backend, operation="write_index", reason=str(e))
            )

        return Ok(EnrolmentRequest(label=label, backend=self.backend, csr_pem=csr_pem))

    def install_certificate(
        self, label: str, certificate_pem: str
    ) -> Result[CredentialSource, KeyStoreError]:
        match validate_label(label):
            case Err(e):
                return Err(e)

        index = self._read_index()
        if label not in index:
            return Err(
                KeyNotFoundError(
                    backend=self.backend, label=label, location=str(self._keychain_path)
                )
            )
        entry = index[label]

        # The keychain cannot tell us whether this certificate belongs to the key
        # it holds, so check against the fingerprint recorded at generate time.
        try:
            cert = x509.load_pem_x509_certificate(certificate_pem.encode())
        except (ValueError, TypeError) as e:
            return Err(
                KeyStoreOperationError(
                    backend=self.backend,
                    operation="install_certificate",
                    reason=f"certificate is not valid PEM: {e}",
                )
            )
        if _public_key_fingerprint(cert.public_key()) != entry.public_key_sha256:
            return Err(
                KeyStoreOperationError(
                    backend=self.backend,
                    operation="install_certificate",
                    reason=(
                        "certificate public key does not match the key generated for "
                        f"'{label}' (wrong certificate, or the key was regenerated "
                        "after the CSR was issued)"
                    ),
                )
            )

        match self._ensure_keychain():
            case Err(e):
                return Err(e)

        tmpdir = tempfile.mkdtemp(prefix="iam-ra-cert-")
        try:
            cert_file = Path(tmpdir) / "cert.pem"
            cert_file.write_text(certificate_pem)
            match self._run(
                ["import", str(cert_file), "-k", str(self._keychain_path), "-A"],
                "import_certificate",
            ):
                case Err(e):
                    return Err(e)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

        return Ok(
            KeychainCredentialSource(
                subject_common_name=entry.common_name,
                keychain_path=self._keychain_path,
            )
        )

    def locate(self, label: str) -> Result[CredentialSource, KeyStoreError]:
        index = self._read_index()
        if label not in index:
            return Err(
                KeyNotFoundError(
                    backend=self.backend, label=label, location=str(self._keychain_path)
                )
            )
        entry = index[label]

        match self._check_platform():
            case Err(e):
                return Err(e)

        # An index entry alone does not prove an identity exists - the key may
        # have been generated but its certificate never installed.
        match self._run(["find-identity", str(self._keychain_path)], "find_identity"):
            case Err(e):
                return Err(e)
            case Ok(out):
                pass

        if entry.common_name not in out:
            return Err(
                KeyNotFoundError(
                    backend=self.backend,
                    label=label,
                    location=(
                        f"{self._keychain_path}: no identity for CN={entry.common_name}. "
                        "The key exists but its certificate has not been installed."
                    ),
                )
            )

        return Ok(
            KeychainCredentialSource(
                subject_common_name=entry.common_name,
                keychain_path=self._keychain_path,
            )
        )

    def _delete_identity(self, common_name: str) -> None:
        """Best-effort removal of an identity by certificate common name.

        Failure is ignored: the identity may not exist yet (key generated but
        certificate never installed), which is not an error for the callers.
        """
        self._run(
            ["delete-identity", "-c", common_name, str(self._keychain_path)],
            "delete_identity",
        )

    def delete(self, label: str) -> Result[None, KeyStoreError]:
        match validate_label(label):
            case Err(e):
                return Err(e)

        index = self._read_index()
        if label not in index:
            return Ok(None)  # idempotent

        match self._check_platform():
            case Err(e):
                return Err(e)

        self._delete_identity(index[label].common_name)
        del index[label]
        try:
            self._write_index(index)
        except OSError as e:
            return Err(
                KeyStoreOperationError(backend=self.backend, operation="write_index", reason=str(e))
            )

        # Note: if the certificate was never installed there is no identity to
        # delete, and `security` offers no way to remove a bare private key. Such
        # a key is left behind. It is inert - non-extractable, and with no
        # certificate it cannot be selected by --cert-selector or used to sign.
        return Ok(None)


# =============================================================================
# Factory
# =============================================================================


def get_keystore(
    backend: KeyStoreBackend, *, root: Path | None = None
) -> Result[KeyStore, KeyStoreOperationError]:
    """Return a key store for ``backend``.

    ``root`` applies to the ``files`` backend only; the keychain backend takes
    its location from the user's Library, or from explicit arguments when
    constructed directly.
    """
    if backend == "files":
        return Ok(FileKeyStore(root=root))
    if backend == "macosKeychain":
        return Ok(KeychainKeyStore())
    return Err(
        KeyStoreOperationError(
            backend=backend,
            operation="get_keystore",
            reason=f"unknown key store backend {backend!r}",
        )
    )
