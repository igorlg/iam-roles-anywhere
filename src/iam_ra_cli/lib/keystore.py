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
``macosKeychain``  non-extractable key in a dedicated keychain (added later).
"""

import os
import re
import shutil
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

type KeyStoreBackend = Literal["files", "macosKeychain"]

type KeyStoreError = KeyAlreadyExistsError | KeyNotFoundError | KeyStoreOperationError

# A label names one key within a store. Restricted to a single safe path
# component so it can be used directly as a directory name and as a keychain
# item label without escaping or traversal concerns.
_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")

# Private key: owner read/write only. Directory: owner-only, so the key is not
# discoverable by listing even briefly.
_KEY_FILE_MODE = 0o600
_KEY_DIR_MODE = 0o700
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

    The key is written via ``os.open`` with the mode supplied up front, so it is
    never briefly readable by others - unlike write-then-``chmod``.

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
            self._dir(label).mkdir(parents=True, exist_ok=True, mode=_KEY_DIR_MODE)
            # mkdir's mode is subject to umask, and is a no-op if the directory
            # already existed, so set it explicitly.
            self._dir(label).chmod(_KEY_DIR_MODE)
            # Open with the final mode so there is no window where the key file
            # exists with broader permissions.
            fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, _KEY_FILE_MODE)
            try:
                os.write(fd, key_pem.encode())
            finally:
                os.close(fd)
            # Enforce the mode even if the file pre-existed with a laxer one.
            key_path.chmod(_KEY_FILE_MODE)
        except OSError as e:
            return Err(
                KeyStoreOperationError(
                    backend=self.backend, operation="generate", reason=str(e)
                )
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
            return Err(
                KeyNotFoundError(backend=self.backend, label=label, location=str(key_path))
            )

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

        return Ok(
            FileCredentialSource(certificate_path=cert_path, private_key_path=key_path)
        )

    def locate(self, label: str) -> Result[CredentialSource, KeyStoreError]:
        key_path = self.key_path(label)
        cert_path = self.certificate_path(label)
        if not key_path.exists():
            return Err(
                KeyNotFoundError(backend=self.backend, label=label, location=str(key_path))
            )
        if not cert_path.exists():
            return Err(
                KeyNotFoundError(backend=self.backend, label=label, location=str(cert_path))
            )
        return Ok(
            FileCredentialSource(certificate_path=cert_path, private_key_path=key_path)
        )

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


def _check_certificate_matches_key(
    certificate_pem: str, private_key_pem: str
) -> Result[None, str]:
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
# Factory
# =============================================================================


def get_keystore(
    backend: KeyStoreBackend, *, root: Path | None = None
) -> Result[KeyStore, KeyStoreOperationError]:
    """Return a key store for ``backend``.

    ``macosKeychain`` is declared in :data:`KeyStoreBackend` but not yet
    implemented; asking for it fails explicitly rather than silently falling
    back to a less protected store.
    """
    if backend == "files":
        return Ok(FileKeyStore(root=root))
    return Err(
        KeyStoreOperationError(
            backend=backend,
            operation="get_keystore",
            reason=f"key store backend {backend!r} is not implemented yet",
        )
    )
