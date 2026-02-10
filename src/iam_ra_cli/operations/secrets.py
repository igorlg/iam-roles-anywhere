"""Secrets file operations - SOPS-encrypted secrets for Nix deployment."""

from dataclasses import dataclass
from pathlib import Path

from botocore.exceptions import ClientError

from iam_ra_cli.lib.aws import AwsContext
from iam_ra_cli.lib.errors import (
    SecretsError,
    SecretsFileExistsError,
    SecretsManagerReadError,
    SOPSEncryptError,
)
from iam_ra_cli.lib.result import Err, Ok, Result
from iam_ra_cli.lib.sops import create_secrets_yaml, get_secrets_path, write_and_encrypt


@dataclass(frozen=True, slots=True)
class SecretsFileResult:
    """Result of creating secrets file."""

    path: Path
    encrypted: bool


def create_secrets_file(
    ctx: AwsContext,
    hostname: str,
    certificate_secret_arn: str,
    private_key_secret_arn: str,
    trust_anchor_arn: str,
    profile_arn: str,
    role_arn: str,
    output_path: Path | None = None,
    encrypt: bool = True,
    overwrite: bool = False,
) -> Result[SecretsFileResult, SecretsError]:
    """Create a SOPS-encrypted secrets file for Nix deployment.

    Args:
        ctx: AWS context
        hostname: Host identifier
        certificate_secret_arn: Secrets Manager ARN for certificate
        private_key_secret_arn: Secrets Manager ARN for private key
        trust_anchor_arn: Trust Anchor ARN
        profile_arn: Roles Anywhere Profile ARN
        role_arn: IAM Role ARN
        output_path: Output path (default: secrets/hosts/<hostname>/iam-ra.yaml)
        encrypt: Whether to encrypt with SOPS
        overwrite: Whether to overwrite existing file
    """
    # Determine output path
    if output_path is None:
        try:
            path = get_secrets_path(hostname)
        except RuntimeError as e:
            return Err(SOPSEncryptError(Path("."), str(e)))
    else:
        path = output_path

    # Check if file exists
    if path.exists() and not overwrite:
        return Err(SecretsFileExistsError(path))

    # Retrieve secrets from Secrets Manager
    try:
        cert_response = ctx.secrets.get_secret_value(SecretId=certificate_secret_arn)
        certificate = cert_response["SecretString"]
    except ClientError as e:
        return Err(SecretsManagerReadError(certificate_secret_arn, str(e)))

    try:
        key_response = ctx.secrets.get_secret_value(SecretId=private_key_secret_arn)
        private_key = key_response["SecretString"]
    except ClientError as e:
        return Err(SecretsManagerReadError(private_key_secret_arn, str(e)))

    # Create YAML content
    yaml_content = create_secrets_yaml(
        hostname=hostname,
        certificate=certificate,
        private_key=private_key,
        trust_anchor_arn=trust_anchor_arn,
        profile_arn=profile_arn,
        role_arn=role_arn,
        region=ctx.region,
    )

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
