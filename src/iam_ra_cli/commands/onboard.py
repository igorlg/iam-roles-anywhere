"""Onboard command - generate host certificate and deploy host stack."""

import click
from pathlib import Path

from iam_ra_cli.lib import cfn, crypto, paths, state
from iam_ra_cli.lib.aws import get_secret
from iam_ra_cli.lib.storage import s3
from iam_ra_cli.lib.templates import get_template_path
from iam_ra_cli.lib.sops import create_secrets_yaml, write_and_encrypt, get_secrets_path
from iam_ra_cli.models import Arn, CAMode, Host, State


HOST_TEMPLATE = "host.yaml"

DEFAULT_NAMESPACE = "default"
DEFAULT_REGION = "ap-southeast-2"


def _stack_name(namespace: str, hostname: str) -> str:
    """Generate stack name for a host."""
    return f"iam-ra-{namespace}-host-{hostname}"


def _load_template(name: str) -> str:
    """Load CloudFormation template body."""
    path = get_template_path(name)
    return path.read_text()


def _require_initialized(namespace: str, region: str, profile: str | None) -> State:
    """Load state and ensure namespace is initialized."""
    current = state.load(namespace, region, profile)
    if current is None or not current.is_initialized:
        raise click.ClickException(
            f"Namespace '{namespace}' is not initialized. Run 'iam-ra init' first."
        )
    return current


@click.command()
@click.argument("hostname")
@click.option(
    "--role",
    "-R",
    required=True,
    help="Role name to associate with this host (must exist)",
)
@click.option(
    "--namespace",
    "-n",
    default=DEFAULT_NAMESPACE,
    show_default=True,
    help="Namespace identifier",
)
@click.option(
    "--region",
    "-r",
    default=DEFAULT_REGION,
    show_default=True,
    help="AWS region",
)
@click.option(
    "--profile",
    "-p",
    default=None,
    help="AWS profile",
)
@click.option(
    "--validity-days",
    default=365,
    show_default=True,
    help="Certificate validity in days",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    default=None,
    help="Output path for SOPS file (default: secrets/hosts/<hostname>/iam-ra.yaml)",
)
@click.option(
    "--skip-sops",
    is_flag=True,
    help="Skip creating SOPS-encrypted secrets file",
)
@click.option(
    "--force",
    "-f",
    is_flag=True,
    help="Overwrite existing host/secrets",
)
def onboard(
    hostname: str,
    role: str,
    namespace: str,
    region: str,
    profile: str | None,
    validity_days: int,
    output: str | None,
    skip_sops: bool,
    force: bool,
) -> None:
    """Onboard a host to IAM Roles Anywhere.

    Generates a host certificate, stores it in Secrets Manager, and
    optionally creates a SOPS-encrypted secrets file for Nix deployment.

    HOSTNAME is the identifier for this host (used in certificate CN).

    \b
    Examples:
      iam-ra onboard myhost --role admin
      iam-ra onboard myhost --role readonly --validity-days 90
      iam-ra onboard webserver --role app --skip-sops
    """
    current = _require_initialized(namespace, region, profile)
    assert current.init is not None
    assert current.ca is not None

    # Validate role exists
    if role not in current.roles:
        raise click.ClickException(
            f"Role '{role}' not found. Create it with: iam-ra role create {role}"
        )

    # Check if host already exists
    if hostname in current.hosts and not force:
        existing = current.hosts[hostname]
        click.echo(f"Host '{hostname}' already onboarded:")
        click.echo(f"  Stack:     {existing.stack_name}")
        click.echo(f"  Role:      {existing.role_name}")
        click.echo(f"  Cert ARN:  {existing.certificate_secret_arn}")
        click.echo()
        click.echo("Use --force to re-onboard (will regenerate certificate).")
        return

    click.echo(f"Onboarding host: {hostname}")
    click.echo(f"  Namespace: {namespace}")
    click.echo(f"  Role:      {role}")
    click.echo(f"  Validity:  {validity_days} days")
    click.echo()

    # Get bucket name from state
    bucket_name = current.init.bucket_arn.resource_id

    # Step 1: Generate host certificate
    click.echo("[1/3] Generating host certificate...")

    if current.ca.mode == CAMode.SELF_SIGNED:
        # Load CA key from local storage
        ca_key_path = paths.data_dir() / namespace / "ca-private-key.pem"
        if not ca_key_path.exists():
            raise click.ClickException(
                f"CA private key not found at {ca_key_path}. "
                "Was the CA created on a different machine?"
            )

        # Load CA cert from S3
        ca_cert_key = f"{namespace}/ca/certificate.pem"
        ca_cert_pem = s3.read(bucket_name, ca_cert_key, region, profile)
        if not ca_cert_pem:
            raise click.ClickException(
                f"CA certificate not found in S3 at s3://{bucket_name}/{ca_cert_key}"
            )

        ca_key_pem = ca_key_path.read_text()

        # Generate host certificate
        host_keypair = crypto.generate_host_cert(
            hostname=hostname,
            ca_cert_pem=ca_cert_pem,
            ca_key_pem=ca_key_pem,
            validity_days=validity_days,
        )

    elif current.ca.mode in (CAMode.PCA_NEW, CAMode.PCA_EXISTING):
        # TODO: Use ACM PCA to issue certificate
        raise click.ClickException(
            "PCA certificate issuance not yet implemented. Use self-signed CA mode for now."
        )

    else:
        raise click.ClickException(f"Unknown CA mode: {current.ca.mode}")

    click.echo(f"       Certificate generated for CN={hostname}")

    # Step 2: Upload cert/key to S3
    click.echo("[2/3] Uploading certificate to S3...")

    cert_s3_key = f"{namespace}/hosts/{hostname}/certificate.pem"
    key_s3_key = f"{namespace}/hosts/{hostname}/private-key.pem"

    s3.write(bucket_name, cert_s3_key, host_keypair.certificate, region, profile)
    s3.write(bucket_name, key_s3_key, host_keypair.private_key, region, profile)

    click.echo(f"       s3://{bucket_name}/{cert_s3_key}")
    click.echo(f"       s3://{bucket_name}/{key_s3_key}")

    # Step 3: Deploy host stack (uses SSM resolve for fetcher ARN and KMS key)
    click.echo("[3/3] Deploying host stack...")

    stack = _stack_name(namespace, hostname)
    template = _load_template(HOST_TEMPLATE)

    outputs = cfn.deploy(
        stack_name=stack,
        template_body=template,
        region=region,
        profile=profile,
        parameters={
            "Namespace": namespace,
            "Hostname": hostname,
            "CertificateS3Key": cert_s3_key,
            "PrivateKeyS3Key": key_s3_key,
        },
        tags={"iam-ra:namespace": namespace, "iam-ra:hostname": hostname},
    )

    cert_secret_arn = Arn(outputs["CertificateSecretArn"])
    key_secret_arn = Arn(outputs["PrivateKeySecretArn"])

    click.echo(f"       Cert secret: {cert_secret_arn}")
    click.echo(f"       Key secret:  {key_secret_arn}")

    # Update state
    new_host = Host(
        stack_name=stack,
        hostname=hostname,
        role_name=role,
        certificate_secret_arn=cert_secret_arn,
        private_key_secret_arn=key_secret_arn,
    )
    current.hosts[hostname] = new_host
    state.save(current, region, profile)

    click.echo()
    click.secho(f"Host '{hostname}' onboarded successfully!", fg="green", bold=True)

    # Step 4 (optional): Create SOPS file
    if not skip_sops:
        click.echo()
        click.echo("Creating SOPS-encrypted secrets file...")

        # Determine output path
        if output:
            output_path = Path(output)
        else:
            output_path = get_secrets_path(hostname)

        if output_path.exists() and not force:
            click.echo(f"  Secrets file already exists: {output_path}")
            click.echo("  Use --force to overwrite.")
        else:
            # Get role info for the secrets file
            role_info = current.roles[role]

            # Retrieve actual secrets from Secrets Manager
            certificate = get_secret(str(cert_secret_arn), region, profile)
            private_key = get_secret(str(key_secret_arn), region, profile)

            yaml_content = create_secrets_yaml(
                hostname=hostname,
                certificate=certificate,
                private_key=private_key,
                trust_anchor_arn=str(current.ca.trust_anchor_arn),
                profile_arn=str(role_info.profile_arn),
                role_arn=str(role_info.role_arn),
                region=region,
            )

            # Write and encrypt
            try:
                write_and_encrypt(yaml_content, output_path)
                click.echo(f"  Saved: {output_path}")
            except RuntimeError as e:
                click.echo(f"  Warning: Could not encrypt with SOPS: {e}")
                click.echo("  You may need to encrypt manually or configure .sops.yaml")

    # Print next steps
    click.echo()
    click.echo("Next steps:")
    click.echo()
    click.echo(f"1. Add to your Nix host configuration ({hostname}):")
    click.echo()
    click.echo("   programs.iamRolesAnywhere = {")
    click.echo("     enable = true;")
    click.echo('     secretsPath = "/path/to/secrets";  # Your sops-nix path')
    click.echo("   };")
    click.echo()
    click.echo("2. Deploy and verify:")
    click.echo()
    click.echo("   aws sts get-caller-identity --profile iam-ra")
