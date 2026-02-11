"""Local file storage for state cache."""

import time
from pathlib import Path


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
