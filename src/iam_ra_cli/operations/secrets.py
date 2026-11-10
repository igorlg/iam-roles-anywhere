"""Secrets operations - hand host cert + key to Nix deployment.

Either a SOPS-encrypted file in the Nix repo (default), or a 1Password
item referenced by the Nix module's ``certificate.keyRef``.
"""

from dataclasses import dataclass
from pathlib import Path

from botocore.exceptions import ClientError

from iam_ra_cli.lib import onepassword
from iam_ra_cli.lib.aws import AwsContext
from iam_ra_cli.lib.errors import (
    OnePasswordError,
    SecretsError,
    SecretsFileExistsError,
    SecretsManagerReadError,
    SOPSEncryptError,
)
from iam_ra_cli.lib.result import Err, Ok, Result
from iam_ra_cli.lib.sops import (
    SopsProfile,
    SopsSecrets,
    create_secrets_yaml,
    get_secrets_path,
    write_and_encrypt,
)


@dataclass(frozen=True, slots=True)
class SecretsFileResult:
    """Result of creating secrets file."""

    path: Path
    encrypted: bool


def _read_host_secrets(
    ctx: AwsContext,
    certificate_secret_arn: str,
    private_key_secret_arn: str,
) -> Result[tuple[str, str], SecretsManagerReadError]:
    """Fetch (certificate_pem, private_key_pem) from Secrets Manager."""
    pems: list[str] = []
    for arn in (certificate_secret_arn, private_key_secret_arn):
        try:
            pems.append(ctx.secrets.get_secret_value(SecretId=arn)["SecretString"])
        except ClientError as e:
            return Err(SecretsManagerReadError(arn, str(e)))
    return Ok((pems[0], pems[1]))


def create_secrets_file(
    ctx: AwsContext,
    hostname: str,
    certificate_secret_arn: str,
    private_key_secret_arn: str,
    trust_anchor_arn: str,
    account_id: str,
    profiles: tuple[SopsProfile, ...],
    namespace: str = "default",
    output_path: Path | None = None,
    encrypt: bool = True,
    overwrite: bool = False,
) -> Result[SecretsFileResult, SecretsError]:
    """Create a SOPS-encrypted v2 secrets file for Nix deployment.

    Args:
        ctx: AWS context
        hostname: Host identifier (for the file header)
        certificate_secret_arn: Secrets Manager ARN holding the PEM cert
        private_key_secret_arn: Secrets Manager ARN holding the PEM key
        trust_anchor_arn: Trust Anchor ARN
        account_id: AWS account ID (written into the v2 YAML for
            downstream validation in the Nix module)
        profiles: Tuple of SopsProfile - all roles this host can assume
            using the cert. At least one required.
        output_path: Override output path. If None, uses
            ``secrets/hosts/<hostname>/iam-ra.yaml`` relative to the Nix
            flake root.
        encrypt: Whether to run SOPS encryption after writing.
        overwrite: Whether to overwrite an existing file at output_path.
    """
    # Determine output path
    if output_path is None:
        try:
            path = get_secrets_path(hostname, namespace)
        except RuntimeError as e:
            return Err(SOPSEncryptError(Path("."), str(e)))
    else:
        path = output_path

    # Check if file exists
    if path.exists() and not overwrite:
        return Err(SecretsFileExistsError(path))

    # Retrieve cert + key from Secrets Manager
    match _read_host_secrets(ctx, certificate_secret_arn, private_key_secret_arn):
        case Err() as e:
            return e
        case Ok((certificate, private_key)):
            pass

    # Render v2 YAML
    secrets = SopsSecrets(
        certificate=certificate,
        private_key=private_key,
        trust_anchor_arn=trust_anchor_arn,
        account_id=account_id,
        region=ctx.region,
        profiles=profiles,
    )
    yaml_content = create_secrets_yaml(hostname=hostname, secrets=secrets)

    if encrypt:
        # Write and encrypt with SOPS
        try:
            write_and_encrypt(yaml_content, path)
            return Ok(SecretsFileResult(path=path, encrypted=True))
        except RuntimeError as e:
            return Err(SOPSEncryptError(path, str(e)))
    else:
        # Just write plain YAML
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml_content)
        return Ok(SecretsFileResult(path=path, encrypted=False))


def store_in_onepassword(
    ctx: AwsContext,
    hostname: str,
    certificate_secret_arn: str,
    private_key_secret_arn: str,
    vault: str,
    namespace: str = "default",
) -> Result[onepassword.OnePasswordItem, SecretsError]:
    """Copy a host's cert + key from Secrets Manager into a new 1Password
    item ``iam-ra-<hostname>-<namespace>`` (see :mod:`iam_ra_cli.lib.onepassword`).
    """
    match _read_host_secrets(ctx, certificate_secret_arn, private_key_secret_arn):
        case Err() as e:
            return e
        case Ok((certificate, private_key)):
            pass
    title = onepassword.item_title(hostname, namespace)
    try:
        return Ok(onepassword.create_item(vault, title, certificate, private_key))
    except RuntimeError as e:
        return Err(OnePasswordError(title, str(e)))
