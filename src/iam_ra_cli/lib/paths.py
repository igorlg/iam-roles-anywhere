"""XDG-compliant paths for CLI data."""

import os
from pathlib import Path

APP_NAME = "iam-ra"


def config_dir() -> Path:
    """~/.config/iam-ra/"""
    base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / APP_NAME


def data_dir() -> Path:
    """~/.local/share/iam-ra/"""
    base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return base / APP_NAME


def state_dir() -> Path:
    """~/.local/state/iam-ra/

    Host-side mutable state, distinct from :func:`data_dir`. Host private keys
    generated on the host live here - they are machine-local, not portable, and
    deliberately not backed up (the analogy is an SSH host key). ``data_dir`` by
    contrast holds admin-side material such as the self-signed CA key.
    """
    base = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
    return base / APP_NAME


def cache_dir() -> Path:
    """~/.local/share/iam-ra/cache/"""
    return data_dir() / "cache"


def state_cache_path(namespace: str) -> Path:
    """Cache file path for a namespace's state."""
    return cache_dir() / namespace / "state.json"
