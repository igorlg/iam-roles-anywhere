"""1Password integration for IAM Roles Anywhere CLI.

Alternative to :mod:`iam_ra_cli.lib.sops`: the host certificate and
private key go into one 1Password item per host + namespace, and the Nix
module fetches the key at credential time (``certificate.keyRef``).

Secret values reach ``op`` only as a JSON item template on stdin: never
in argv (visible to other processes) and never in a temp file.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass

CERTIFICATE_FIELD = "certificate"
PRIVATE_KEY_FIELD = "private_key"


@dataclass(frozen=True)
class OnePasswordItem:
    """A host's 1Password item and the secret references into it."""

    vault: str
    title: str

    @property
    def certificate_ref(self) -> str:
        return f"op://{self.vault}/{self.title}/{CERTIFICATE_FIELD}"

    @property
    def key_ref(self) -> str:
        return f"op://{self.vault}/{self.title}/{PRIVATE_KEY_FIELD}"


def item_title(hostname: str, namespace: str = "default") -> str:
    """Canonical 1Password item title for a host in a namespace."""
    return f"iam-ra-{hostname}-{namespace}"


def _run_op(args: list[str], stdin: str | None = None) -> str:
    """Run ``op`` and return its stdout; RuntimeError on any failure."""
    try:
        proc = subprocess.run(
            ["op", *args],
            input=stdin,
            # Without input, don't let op inherit (and wait on) our stdin.
            stdin=subprocess.DEVNULL if stdin is None else None,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as e:
        raise RuntimeError("1Password CLI 'op' not found on PATH") from e
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or f"op exited with status {proc.returncode}")
    return proc.stdout


def create_item(vault: str, title: str, certificate: str, private_key: str) -> OnePasswordItem:
    """Create the host item: a Secure Note with the certificate (plain
    text) and the private key (concealed).

    Refuses if any item in ``vault`` already has exactly this title, so
    re-running never creates a duplicate. Listing the vault (rather than
    ``op item get <title>``) keeps "not found" apart from other failures.

    Raises:
        RuntimeError: ``op`` is missing or failed, or the title is taken.
    """
    items = json.loads(_run_op(["item", "list", "--vault", vault, "--format", "json"]) or "[]")
    ids = [str(i["id"]) for i in items if i.get("title") == title]
    if ids:
        raise RuntimeError(
            f"{len(ids)} item(s) titled '{title}' already in vault '{vault}' "
            f"({', '.join(ids)}); delete them, then re-run 'host onboard' with --overwrite"
        )
    template = {
        "title": title,
        "category": "SECURE_NOTE",
        "fields": [
            {"id": f, "label": f, "type": t, "value": v}
            for f, t, v in (
                (CERTIFICATE_FIELD, "STRING", certificate),
                (PRIVATE_KEY_FIELD, "CONCEALED", private_key),
            )
        ],
    }
    _run_op(["item", "create", "--vault", vault, "-"], stdin=json.dumps(template))
    return OnePasswordItem(vault=vault, title=title)
