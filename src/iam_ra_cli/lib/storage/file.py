"""Local file storage for state cache, and secure writes for private keys."""

import os
import tempfile
import time
from pathlib import Path

# A private key's directory is owner-only, so the key is not even discoverable
# by listing. The key itself is 0600, which is what mkstemp creates.
PRIVATE_KEY_DIR_MODE = 0o700


def write_private_key(path: Path, pem: str) -> None:
    """Write a private key so it is never readable by anyone else, even briefly.

    Raises OSError on failure.

    The key is written to a fresh 0600 temp file and renamed into place, rather
    than written and then chmodded. Write-then-chmod leaves a window in which
    the key exists with permissions derived from the umask - for the common
    umask of 022 that means world-readable, which is a race another local
    process can win. Renaming also means an existing key is never rewritten in
    place, a symlink planted at ``path`` is replaced rather than followed, and a
    failed write leaves the old key intact.

    Every directory this function *creates* is made owner-only too, not just the
    immediate parent. Under a permissive umask an intermediate directory would
    otherwise be world-writable, which lets an attacker rename it and substitute
    their own - so the key's own 0600 would not save you. Directories that
    already exist are left alone, apart from the immediate parent, since they may
    be shared with other applications (``~/.local/share``).
    """
    directory = path.parent

    # Work out which ancestors are missing before creating any of them, so each
    # can be created with the right mode rather than the default.
    missing: list[Path] = []
    probe = directory
    while not probe.exists():
        missing.append(probe)
        if probe.parent == probe:
            break
        probe = probe.parent

    for parent in reversed(missing):
        parent.mkdir(mode=PRIVATE_KEY_DIR_MODE, exist_ok=True)
        # mkdir's mode is masked by the umask, so set it explicitly.
        parent.chmod(PRIVATE_KEY_DIR_MODE)

    # The immediate parent may have pre-existed with laxer permissions.
    directory.chmod(PRIVATE_KEY_DIR_MODE)

    # mkstemp creates with O_EXCL and mode 0600, so the key is never readable by
    # anyone else, and nothing already at that name is opened.
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(pem)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise


def read(path: Path) -> str | None:
    """Read file contents, or None if doesn't exist."""
    if not path.exists():
        return None
    return path.read_text()


def write(path: Path, data: str) -> None:
    """Write data to file, creating parent dirs if needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data)


def is_fresh(path: Path, ttl_seconds: int) -> bool:
    """Check if file exists and was modified within TTL."""
    if not path.exists():
        return False
    age = time.time() - path.stat().st_mtime
    return age < ttl_seconds


def delete(path: Path) -> None:
    """Delete file if it exists."""
    if path.exists():
        path.unlink()
