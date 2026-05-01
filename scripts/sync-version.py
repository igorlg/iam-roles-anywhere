#!/usr/bin/env python3
"""
Sync version from VERSION file to all locations in the repo.

Usage:
    ./scripts/sync-version.py          # Sync current VERSION to all files
    ./scripts/sync-version.py 0.2.0    # Set new version and sync
    ./scripts/sync-version.py --check  # Check if versions are in sync

Locations updated:
    - VERSION (source of truth)
    - pyproject.toml
    - src/iam_ra_cli/__init__.py
    - src/iam_ra_cli/data/cloudformation/*.yaml (Metadata)
    - uv.lock (via `uv lock`)
"""

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
VERSION_FILE = REPO_ROOT / "VERSION"
PYPROJECT_FILE = REPO_ROOT / "pyproject.toml"
INIT_FILE = REPO_ROOT / "src" / "iam_ra_cli" / "__init__.py"
CFN_DIR = REPO_ROOT / "src" / "iam_ra_cli" / "data" / "cloudformation"
UV_LOCK_FILE = REPO_ROOT / "uv.lock"

# Semver pattern
SEMVER_PATTERN = re.compile(r"^\d+\.\d+\.\d+(-[\w.]+)?$")


def read_version() -> str:
    """Read version from VERSION file."""
    return VERSION_FILE.read_text().strip()


def write_version(version: str) -> None:
    """Write version to VERSION file."""
    VERSION_FILE.write_text(f"{version}\n")


def sync_pyproject(version: str, check_only: bool = False) -> bool:
    """Sync version in pyproject.toml."""
    content = PYPROJECT_FILE.read_text()
    pattern = re.compile(r'^version\s*=\s*"[^"]+"', re.MULTILINE)
    new_line = f'version = "{version}"'

    match = pattern.search(content)
    if not match:
        print(f"ERROR: Could not find version in {PYPROJECT_FILE}")
        return False

    current = match.group(0)
    if current == new_line:
        return True

    if check_only:
        print(f"MISMATCH: {PYPROJECT_FILE} has {current}, expected {new_line}")
        return False

    new_content = pattern.sub(new_line, content)
    PYPROJECT_FILE.write_text(new_content)
    print(f"Updated {PYPROJECT_FILE}")
    return True


def sync_init(version: str, check_only: bool = False) -> bool:
    """Sync version in __init__.py."""
    content = INIT_FILE.read_text()
    pattern = re.compile(r'^__version__\s*=\s*"[^"]+"', re.MULTILINE)
    new_line = f'__version__ = "{version}"'

    match = pattern.search(content)
    if not match:
        print(f"ERROR: Could not find __version__ in {INIT_FILE}")
        return False

    current = match.group(0)
    if current == new_line:
        return True

    if check_only:
        print(f"MISMATCH: {INIT_FILE} has {current}, expected {new_line}")
        return False

    new_content = pattern.sub(new_line, content)
    INIT_FILE.write_text(new_content)
    print(f"Updated {INIT_FILE}")
    return True


def sync_cfn_templates(version: str, check_only: bool = False) -> bool:
    """Sync version in CloudFormation template Outputs.Version."""
    all_ok = True

    for cfn_file in CFN_DIR.glob("*.yaml"):
        content = cfn_file.read_text()

        # Pattern matches the Version output value in CFN templates:
        #   Version:
        #     Description: Template version
        #     Value: "X.Y.Z"
        pattern = re.compile(
            r"(^\s+Version:\s*\n\s+Description:[^\n]*\n\s+Value:\s*)\"[^\"]+\"", re.MULTILINE
        )
        new_value = f'\\g<1>"{version}"'

        match = pattern.search(content)
        if not match:
            # Template doesn't have Version output - skip
            continue

        current = match.group(0)
        expected = pattern.sub(new_value, current)

        if current == expected:
            continue

        if check_only:
            print(f"MISMATCH: {cfn_file.name} version mismatch")
            all_ok = False
            continue

        new_content = pattern.sub(new_value, content)
        cfn_file.write_text(new_content)
        print(f"Updated {cfn_file}")

    return all_ok


def sync_uv_lock(version: str, check_only: bool = False) -> bool:
    """Sync uv.lock by invoking `uv lock`.

    uv.lock embeds the workspace package's version, so any VERSION bump
    needs the lockfile regenerated. We shell out to `uv lock` rather than
    regex-patching because the lockfile format is opaque/internal to uv.

    Args:
        version: Target version (informational - uv reads it from pyproject.toml)
        check_only: If True, run `uv lock --check` to verify without writing

    Returns:
        True if in sync (or successfully synced), False on mismatch/error.

    Behaviour when `uv` is missing:
        Fails (returns False). The project's dev shell and CI always have
        uv available, so this is a configuration error worth surfacing.
        For the rare case of running this script in an environment without
        uv (e.g. a minimal release rebuild), set the IAM_RA_SKIP_UV_LOCK
        environment variable to skip this check.
    """
    if not UV_LOCK_FILE.exists():
        # No lockfile to sync - skip silently (e.g. fresh checkout before first sync)
        return True

    if os.environ.get("IAM_RA_SKIP_UV_LOCK"):
        print("NOTE: IAM_RA_SKIP_UV_LOCK set; skipping uv.lock sync.", file=sys.stderr)
        return True

    uv_bin = shutil.which("uv")
    if uv_bin is None:
        print(
            "ERROR: `uv` not found on PATH. Install uv "
            "(https://docs.astral.sh/uv/) or set IAM_RA_SKIP_UV_LOCK=1 to skip.",
            file=sys.stderr,
        )
        return False

    cmd = [uv_bin, "lock"]
    if check_only:
        cmd.append("--check")

    try:
        result = subprocess.run(
            cmd,
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as e:
        print(f"ERROR: Failed to invoke `uv lock`: {e}", file=sys.stderr)
        return False

    if result.returncode != 0:
        if check_only:
            print(f"MISMATCH: {UV_LOCK_FILE} is out of sync with pyproject.toml")
            if result.stderr:
                print(result.stderr.strip(), file=sys.stderr)
        else:
            print("ERROR: `uv lock` failed:", file=sys.stderr)
            print(result.stderr, file=sys.stderr)
        return False

    # Success: report only if we actually wrote something (non-check mode).
    if not check_only:
        print(f"Updated {UV_LOCK_FILE}")
    return True


def main() -> int:
    args = sys.argv[1:]

    # Check mode
    if "--check" in args:
        version = read_version()
        print(f"Checking version sync (VERSION={version})...")
        ok = all(
            [
                sync_pyproject(version, check_only=True),
                sync_init(version, check_only=True),
                sync_cfn_templates(version, check_only=True),
                sync_uv_lock(version, check_only=True),
            ]
        )
        if ok:
            print("All versions in sync!")
            return 0
        else:
            print("Version mismatch detected!")
            return 1

    # Set new version if provided
    if args and not args[0].startswith("-"):
        new_version = args[0]
        if not SEMVER_PATTERN.match(new_version):
            print(f"ERROR: Invalid semver format: {new_version}")
            print("Expected: X.Y.Z or X.Y.Z-prerelease")
            return 1
        write_version(new_version)
        print(f"Set VERSION to {new_version}")
        version = new_version
    else:
        version = read_version()
        print(f"Syncing version {version}...")

    # Sync all locations
    sync_pyproject(version)
    sync_init(version)
    sync_cfn_templates(version)
    # uv.lock must be synced AFTER pyproject.toml since `uv lock` reads the
    # new version from pyproject.toml.
    sync_uv_lock(version)

    print("Done!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
