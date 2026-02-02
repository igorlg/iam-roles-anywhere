"""Onboard command for IAM Roles Anywhere CLI.

TODO: Make SOPS integration optional
--------------------------------------
Currently, this command requires SOPS to be configured (looks for .sops.yaml
and calls `sops -e` to encrypt). To make this flake truly secrets-manager
agnostic, we should:

1. Add a --no-encrypt flag that outputs plain YAML (user encrypts with their tool)
2. Or add a --secrets-backend flag (sops, agenix, plain)
3. Or always output plain YAML and remove SOPS from the CLI entirely

The Nix modules are already secrets-manager agnostic (they just take paths).
The CLI is the only component with a hard SOPS dependency.

For now, users who don't use SOPS can:
- Run with --skip-deploy and manually fetch secrets from AWS Secrets Manager
- Use the AWS Console/CLI to retrieve certificate and private key
- Create their own secrets file in their preferred format
"""

import click
from pathlib import Path
from typing import Optional

from ..lib.aws import get_secret
from ..lib.cfn import get_stack_outputs, stack_exists
from ..lib.sops import (
    create_secrets_yaml,
    write_and_encrypt,
    get_secrets_path,
    get_nix_repo_root,
)
from ..lib.templates import SAMRunner


# Default configuration
DEFAULT_REGION = "ap-southeast-2"
DEFAULT_SSM_PREFIX = "/iam-ra"
DEFAULT_STACK_PREFIX = "iam-ra"

# Stack templates
HOST_STACK_TEMPLATE = "host-stack.yaml"


@click.command()
@click.argument("hostname")
@click.option(
    "--region",
    "-r",
    default=DEFAULT_REGION,
    show_default=True,
    help="AWS region for deployment",
)
@click.option(
    "--stack-prefix",
    default=DEFAULT_STACK_PREFIX,
    show_default=True,
    help="Prefix for CloudFormation stack names",
)
@click.option(
    "--ssm-prefix",
    default=DEFAULT_SSM_PREFIX,
    show_default=True,
    help="SSM Parameter Store prefix used by the stacks",
)
@click.option(
    "--profile",
    "-p",
    default=None,
    help="AWS profile to use for API calls",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    default=None,
    help="Output path for SOPS file (default: secrets/hosts/<hostname>/iam-ra.yaml)",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Show what would be done without making changes",
)
@click.option(
    "--force",
    "-f",
    is_flag=True,
    help="Overwrite existing secrets file",
)
@click.option(
    "--skip-deploy",
    is_flag=True,
    help="Skip deploying the host stack (only fetch secrets from existing stack)",
)
@click.option(
    "--policy-arns",
    default=None,
    help="Comma-separated list of IAM policy ARNs to attach to the host role",
)
def onboard(
    hostname: str,
    region: str,
    stack_prefix: str,
    ssm_prefix: str,
    profile: Optional[str],
    output: Optional[str],
    dry_run: bool,
    force: bool,
    skip_deploy: bool,
    policy_arns: Optional[str],
):
    """
    Onboard a host to IAM Roles Anywhere.

    This command performs the complete onboarding workflow:

    \b
    1. Deploys the host CloudFormation stack (if not already deployed)
       - Creates IAM role for the host
       - Creates IAM Roles Anywhere profile
       - Issues X.509 certificate via the shared certificate issuer
       - Stores certificate and private key in Secrets Manager

    \b
    2. Retrieves credentials from AWS
       - Fetches stack outputs (Role ARN, Profile ARN, Trust Anchor ARN)
       - Retrieves certificate and private key from Secrets Manager

    \b
    3. Creates SOPS-encrypted secrets file
       - Writes to secrets/hosts/<hostname>/iam-ra.yaml
       - Encrypts using the repository's .sops.yaml configuration

    Prerequisites:

    \b
    - IAM Roles Anywhere infrastructure must be initialized (run 'iam-ra init' first)
    - AWS credentials with CloudFormation, Secrets Manager, and IAM permissions
    - SOPS configured with appropriate keys (see .sops.yaml)

    Example:

    \b
        iam-ra onboard myhost                    # Full onboarding
        iam-ra onboard myhost --dry-run          # Preview what would happen
        iam-ra onboard myhost --skip-deploy      # Only fetch secrets (stack exists)
        iam-ra onboard myhost --policy-arns arn:aws:iam::aws:policy/ReadOnlyAccess
    """
    host_stack_name = f"{stack_prefix}-host-{hostname}"

    click.echo(f"Onboarding host: {hostname}")
    click.echo(f"  Region:       {region}")
    click.echo(f"  Stack prefix: {stack_prefix}")
    click.echo(f"  Host stack:   {host_stack_name}")
    click.echo()

    # Check if host stack exists
    click.echo("Checking infrastructure...")
    host_stack_deployed = stack_exists(host_stack_name, region, profile)

    if host_stack_deployed:
        click.echo(f"  Host stack: {host_stack_name} (exists)")
    else:
        click.echo(f"  Host stack: {host_stack_name} (not found)")

    # Determine output path early for existence check
    if output:
        output_path = Path(output)
    else:
        output_path = get_secrets_path(hostname)

    secrets_exist = output_path.exists()
    if secrets_exist:
        click.echo(f"  Secrets file: {output_path} (exists)")
    else:
        click.echo(f"  Secrets file: {output_path} (not found)")

    click.echo()

    # Determine what needs to be done
    need_deploy = not host_stack_deployed and not skip_deploy
    need_secrets = not secrets_exist or force

    if not need_deploy and not need_secrets:
        click.secho("Host is already fully onboarded!", fg="green")
        click.echo()
        click.echo("Use --force to regenerate the secrets file.")
        return

    # Check prerequisites for deployment
    if need_deploy:
        # Verify that the base infrastructure exists
        rootca_stack = f"{stack_prefix}-rootca"
        iamra_stack = f"{stack_prefix}-account"

        if not stack_exists(rootca_stack, region, profile):
            raise click.ClickException(
                f"Root CA stack '{rootca_stack}' not found. "
                "Run 'iam-ra init' first to set up the infrastructure."
            )

        if not stack_exists(iamra_stack, region, profile):
            raise click.ClickException(
                f"IAM RA stack '{iamra_stack}' not found. "
                "Run 'iam-ra init' first to set up the infrastructure."
            )

    if dry_run:
        click.echo("[DRY RUN] Would perform the following:")
        if need_deploy:
            click.echo(f"  - Deploy host stack: {host_stack_name}")
        if need_secrets:
            click.echo(f"  - Create secrets file: {output_path}")
        click.echo()
        click.echo("[DRY RUN] No changes made.")
        return

    # Step 1: Deploy host stack if needed
    if need_deploy:
        click.echo(f"Deploying host stack: {host_stack_name}")

        with SAMRunner(region=region, profile=profile) as sam:
            click.echo("  Building...")
            try:
                # Host stack doesn't have its own Lambda, but SAM build is still needed
                # to process the template
                sam.build(HOST_STACK_TEMPLATE)
                click.echo("  Build complete.")
            except Exception as e:
                raise click.ClickException(f"SAM build failed: {e}")

            click.echo("  Deploying...")

            # Prepare parameters
            host_params = {
                "Hostname": hostname,
                "SSMPrefix": ssm_prefix,
            }
            if policy_arns:
                host_params["PolicyArns"] = policy_arns

            try:
                sam.deploy(
                    template=HOST_STACK_TEMPLATE,
                    stack_name=host_stack_name,
                    parameter_overrides=host_params,
                    tags={
                        "Purpose": "IAM-Roles-Anywhere",
                        "Component": "Host",
                        "Hostname": hostname,
                    },
                )
                click.echo("  Deploy complete.")
            except Exception as e:
                raise click.ClickException(f"Host stack deployment failed: {e}")
    else:
        if skip_deploy:
            click.echo("Skipping stack deployment (--skip-deploy)")
        else:
            click.echo(f"Host stack already exists: {host_stack_name}")

    click.echo()

    # Step 2: Retrieve stack outputs and secrets
    if need_secrets:
        click.echo("Retrieving stack outputs...")
        try:
            outputs = get_stack_outputs(host_stack_name, region, profile)
        except Exception as e:
            raise click.ClickException(f"Failed to get stack outputs: {e}")

        # Extract required values
        role_arn = outputs.get("RoleArn")
        profile_arn = outputs.get("ProfileArn")
        trust_anchor_arn = outputs.get("TrustAnchorArn")
        cert_secret_arn = outputs.get("CertificateSecretArn")
        key_secret_arn = outputs.get("PrivateKeySecretArn")

        # Validate outputs
        missing = []
        if not role_arn:
            missing.append("RoleArn")
        if not profile_arn:
            missing.append("ProfileArn")
        if not trust_anchor_arn:
            missing.append("TrustAnchorArn")
        if not cert_secret_arn:
            missing.append("CertificateSecretArn")
        if not key_secret_arn:
            missing.append("PrivateKeySecretArn")

        if missing:
            raise click.ClickException(
                f"Stack is missing required outputs: {', '.join(missing)}. "
                "The stack may need to be updated or redeployed."
            )

        assert role_arn is not None
        assert profile_arn is not None
        assert trust_anchor_arn is not None
        assert cert_secret_arn is not None
        assert key_secret_arn is not None

        click.echo(f"  Role ARN:         {role_arn}")
        click.echo(f"  Profile ARN:      {profile_arn}")
        click.echo(f"  Trust Anchor ARN: {trust_anchor_arn}")

        # Retrieve secrets
        click.echo("Retrieving certificate and private key...")
        try:
            certificate = get_secret(cert_secret_arn, region, profile)
            private_key = get_secret(key_secret_arn, region, profile)
        except Exception as e:
            raise click.ClickException(f"Failed to retrieve secrets: {e}")

        click.echo("  Certificate: retrieved")
        click.echo("  Private key: retrieved")

        # Get repo root for .sops.yaml
        repo_root = get_nix_repo_root()
        sops_config = repo_root / ".sops.yaml" if repo_root else None

        # Create YAML content
        yaml_content = create_secrets_yaml(
            hostname=hostname,
            certificate=certificate,
            private_key=private_key,
            trust_anchor_arn=trust_anchor_arn,
            profile_arn=profile_arn,
            role_arn=role_arn,
            region=region,
        )

        # Write and encrypt
        click.echo(f"Writing secrets file: {output_path}")
        try:
            write_and_encrypt(yaml_content, output_path, sops_config)
        except RuntimeError as e:
            raise click.ClickException(str(e))

        click.echo("  Encrypted and saved.")

    # Print success and next steps
    click.echo()
    click.secho("Success!", fg="green", bold=True)
    click.echo()
    click.echo("Next steps:")
    click.echo()
    click.echo(f"1. Update the host configuration at hosts/{hostname}/sops.nix:")
    click.echo()
    click.echo("   sops.secrets.iam-ra = {")
    click.echo(f"     sopsFile = ../../../secrets/hosts/{hostname}/iam-ra.yaml;")
    click.echo('     format = "yaml";')
    click.echo("   };")
    click.echo()
    click.echo("   programs.iamRolesAnywhere = {")
    click.echo("     enable = true;")
    click.echo("     secretsPath = config.sops.secrets.iam-ra.path;")
    click.echo("   };")
    click.echo()
    click.echo("2. Deploy the configuration:")
    click.echo()
    click.echo(f"   nxctl deploy {hostname}")
    click.echo()
    click.echo("3. Verify IAM Roles Anywhere is working:")
    click.echo()
    click.echo("   aws sts get-caller-identity --profile iam-ra")
