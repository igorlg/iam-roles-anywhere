"""Tests for lib/storage/file.py - in particular the private-key writer.

The property under test is a security property: a private key must never be
readable by anyone but its owner, *including transiently*. The obvious
implementation - write the file, then chmod it - leaves a window in which the
key exists with permissions derived from the umask, and for the common umask of
022 that means world-readable. A local attacker who wins that race gets the key.

The window itself is invisible from outside, so asserting on the final mode is
not enough. These tests pin down the consequences of writing a fresh file and
renaming it into place instead, each of which the write-then-chmod version fails.
"""

import os
import stat
from pathlib import Path
from unittest.mock import patch

import pytest

from iam_ra_cli.lib.storage.file import write_private_key

# Opaque placeholder. write_private_key never parses its input, and these
# tests are about file permissions, so nothing here needs to look like a key.
KEY_MATERIAL = "test-key-material-not-a-real-key\n"


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


class TestWritePrivateKey:
    @pytest.mark.parametrize("umask", [0o000, 0o077])
    def test_key_and_every_created_directory_are_owner_only(
        self, tmp_path: Path, umask: int
    ) -> None:
        """Not just the immediate parent, whatever the umask.

        A world-writable intermediate lets an attacker rename it and substitute
        their own directory, at which point the key file's own 0600 protects
        nothing - they supply the replacement key. 000 is the most permissive
        umask; 077 checks a restrictive one does not leave a directory unusable.
        """
        root = tmp_path / "share"
        target = root / "iam-ra" / "myns" / "scopes" / "default" / "key.pem"

        original = os.umask(umask)
        try:
            write_private_key(target, KEY_MATERIAL)
        finally:
            os.umask(original)

        assert target.read_text() == KEY_MATERIAL
        assert _mode(target) == 0o600
        for directory in (
            root,
            root / "iam-ra",
            root / "iam-ra" / "myns",
            root / "iam-ra" / "myns" / "scopes",
            target.parent,
        ):
            assert _mode(directory) == 0o700, f"{directory} is {oct(_mode(directory))}"

    def test_leaves_pre_existing_ancestors_alone(self, tmp_path: Path) -> None:
        """Only the immediate parent is retightened; shared dirs are not touched.

        ``~/.local/share`` is not ours to chmod.
        """
        shared = tmp_path / "share"
        shared.mkdir(mode=0o755)

        write_private_key(shared / "iam-ra" / "key.pem", KEY_MATERIAL)

        assert _mode(shared) == 0o755, "a pre-existing shared ancestor was modified"
        assert _mode(shared / "iam-ra") == 0o700

    def test_tightens_a_pre_existing_lax_directory(self, tmp_path: Path) -> None:
        """mkdir's mode is a no-op when the directory already exists."""
        directory = tmp_path / "existing"
        directory.mkdir(mode=0o755)

        write_private_key(directory / "key.pem", KEY_MATERIAL)

        assert _mode(directory) == 0o700

    def test_existing_key_is_replaced_not_rewritten(self, tmp_path: Path) -> None:
        """A new inode, so the old file's lax mode and open readers are not inherited.

        Rewriting in place would let a process that already holds the old file
        open read the new key through it.
        """
        target = tmp_path / "key.pem"
        target.write_text("old")
        target.chmod(0o644)

        fd = os.open(target, os.O_RDONLY)
        try:
            write_private_key(target, KEY_MATERIAL)
            assert os.read(fd, 100) == b"old"
        finally:
            os.close(fd)

        assert _mode(target) == 0o600
        assert target.read_text() == KEY_MATERIAL

    def test_does_not_follow_a_planted_symlink(self, tmp_path: Path) -> None:
        """A symlink at the key path is replaced, never written through."""
        victim = tmp_path / "victim"
        victim.write_text("x")
        victim.chmod(0o644)
        directory = tmp_path / "scope"
        directory.mkdir()
        (directory / "key.pem").symlink_to(victim)

        write_private_key(directory / "key.pem", KEY_MATERIAL)

        assert victim.read_text() == "x"
        assert _mode(victim) == 0o644
        assert not (directory / "key.pem").is_symlink()
        assert (directory / "key.pem").read_text() == KEY_MATERIAL

    def test_failed_write_leaves_old_key_and_no_temp_file(self, tmp_path: Path) -> None:
        """A failure must not destroy the existing key or leave key material behind."""
        target = tmp_path / "key.pem"
        target.write_text("old")

        with (
            patch("iam_ra_cli.lib.storage.file.os.replace", side_effect=OSError("boom")),
            pytest.raises(OSError, match="boom"),
        ):
            write_private_key(target, KEY_MATERIAL)

        assert target.read_text() == "old"
        assert sorted(p.name for p in tmp_path.iterdir()) == ["key.pem"]

    def test_raises_oserror(self, tmp_path: Path) -> None:
        """Errors surface as OSError, not a swallowed failure.

        Silently returning would leave a CA with no key on disk and no error
        reported.
        """
        blocker = tmp_path / "blocker"
        blocker.write_text("i am a file, not a directory")

        with pytest.raises(OSError):
            write_private_key(blocker / "nested" / "key.pem", KEY_MATERIAL)
