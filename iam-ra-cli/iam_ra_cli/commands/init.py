"""Init command for IAM Roles Anywhere CLI."""

import click
from typing import Optional

from ..lib.cfn import stack_exists, get_stack_outputs, get_stack_status
from ..lib.templates import SAMRunner


# Default configuration
DEFAULT_REGION = "ap-southeast-2"
DEFAULT_SSM_PREFIX = "/iam-ra"
DEFAULT_STACK_PREFIX = "iam-ra"

# Stack names
ROOTCA_STACK_TEMPLATE = "account-rootca-stack.yaml"
IAMRA_STACK_TEMPLATE = "account-iamra-stack.yaml"


@click.command()
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
    help="SSM Parameter Store prefix",
)
@click.option(
    "--ca-mode",
    type=click.Choice(["self-managed", "pca-create", "pca-existing"]),
    default="self-managed",
    show_default=True,
    help="Certificate Authority mode",
)
@click.option(
    "--pca-arn",
    default=None,
    help="Existing ACM PCA ARN (required if --ca-mode=pca-existing)",
)
@click.option(
    "--profile",
    "-p",
    default=None,
    help="AWS profile to use for API calls",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Show what would be done without making changes",
)
@click.option(
    "--use-container",
    is_flag=True,
    help="Use Docker container for SAM build (useful for Lambda dependencies)",
)
def init(
    region: str,
    stack_prefix: str,
    ssm_prefix: str,
    ca_mode: str,
    pca_arn: Optional[str],
    profile: Optional[str],
    dry_run: bool,
    use_container: bool,
):
    """
    Initialize IAM Roles Anywhere infrastructure.

    This command deploys the foundational CloudFormation stacks:

    \b
    1. Root CA Stack - Creates or configures the Certificate Authority
       - self-managed: Generates a self-signed CA (default, simplest)
       - pca-create: Creates a new AWS Private CA
       - pca-existing: Uses an existing AWS Private CA

    \b
    2. IAM RA Stack - Creates the IAM Roles Anywhere trust anchor and
       shared certificate issuer Lambda

    Both stacks are deployed idempotently - if they already exist with
    the correct configuration, no changes are made.

    After init, use 'iam-ra onboard <hostname>' to set up individual hosts.

    Example:

    \b
        iam-ra init                           # Default: self-managed CA
        iam-ra init --ca-mode pca-create      # Create new ACM PCA
        iam-ra init --ca-mode pca-existing --pca-arn arn:aws:acm-pca:...
        iam-ra init --dry-run                 # Preview what would happen
    """
    # Validate options
    if ca_mode == "pca-existing" and not pca_arn:
        raise click.ClickException("--pca-arn is required when --ca-mode=pca-existing")

    rootca_stack_name = f"{stack_prefix}-rootca"
    iamra_stack_name = f"{stack_prefix}-account"

    click.echo("IAM Roles Anywhere - Infrastructure Init")
    click.echo()
    click.echo(f"  Region:       {region}")
    click.echo(f"  Stack prefix: {stack_prefix}")
    click.echo(f"  SSM prefix:   {ssm_prefix}")
    click.echo(f"  CA mode:      {ca_mode}")
    if pca_arn:
        click.echo(f"  PCA ARN:      {pca_arn}")
    click.echo()

    # Check current state
    click.echo("Checking existing infrastructure...")

    rootca_exists = stack_exists(rootca_stack_name, region, profile)
    iamra_exists = stack_exists(iamra_stack_name, region, profile)

    if rootca_exists:
        rootca_status = get_stack_status(rootca_stack_name, region, profile)
        click.echo(f"  Root CA stack: {rootca_stack_name} ({rootca_status})")
    else:
        click.echo(f"  Root CA stack: {rootca_stack_name} (not found)")

    if iamra_exists:
        iamra_status = get_stack_status(iamra_stack_name, region, profile)
        click.echo(f"  IAM RA stack:  {iamra_stack_name} ({iamra_status})")
    else:
        click.echo(f"  IAM RA stack:  {iamra_stack_name} (not found)")

    click.echo()

    # Determine what needs to be done
    deploy_rootca = not rootca_exists
    deploy_iamra = not iamra_exists

    if not deploy_rootca and not deploy_iamra:
        click.secho("All infrastructure already exists!", fg="green")
        _show_existing_outputs(rootca_stack_name, iamra_stack_name, region, profile)
        return

    if dry_run:
        click.echo("[DRY RUN] Would deploy:")
        if deploy_rootca:
            click.echo(f"  - Root CA stack: {rootca_stack_name}")
        if deploy_iamra:
            click.echo(f"  - IAM RA stack:  {iamra_stack_name}")
        click.echo()
        click.echo("[DRY RUN] No changes made.")
        return

    # Deploy stacks
    with SAMRunner(region=region, profile=profile) as sam:
        # Step 1: Deploy Root CA stack
        if deploy_rootca:
            click.echo(f"Deploying Root CA stack: {rootca_stack_name}")
            click.echo("  Building...")

            try:
                # Root CA stack has a Lambda (ca_generator)
                sam.build(ROOTCA_STACK_TEMPLATE, use_container=use_container)
                click.echo("  Build complete.")
            except Exception as e:
                raise click.ClickException(f"SAM build failed: {e}")

            click.echo("  Deploying...")

            # Prepare parameters
            rootca_params = {
                "SSMPrefix": ssm_prefix,
                "CAMode": ca_mode,
            }
            if ca_mode == "pca-existing" and pca_arn:
                rootca_params["ExistingPCAArn"] = pca_arn

            try:
                result = sam.deploy(
                    template=ROOTCA_STACK_TEMPLATE,
                    stack_name=rootca_stack_name,
                    parameter_overrides=rootca_params,
                    tags={"Purpose": "IAM-Roles-Anywhere", "Component": "RootCA"},
                )
                click.echo("  Deploy complete.")
            except Exception as e:
                raise click.ClickException(f"Root CA deployment failed: {e}")
        else:
            click.echo(f"Root CA stack already exists: {rootca_stack_name}")

        # Step 2: Deploy IAM RA stack
        if deploy_iamra:
            click.echo(f"Deploying IAM RA stack: {iamra_stack_name}")
            click.echo("  Building...")

            try:
                # IAM RA stack has a Lambda (certificate_issuer)
                sam.build(IAMRA_STACK_TEMPLATE, use_container=use_container)
                click.echo("  Build complete.")
            except Exception as e:
                raise click.ClickException(f"SAM build failed: {e}")

            click.echo("  Deploying...")

            iamra_params = {
                "SSMPrefix": ssm_prefix,
            }

            try:
                result = sam.deploy(
                    template=IAMRA_STACK_TEMPLATE,
                    stack_name=iamra_stack_name,
                    parameter_overrides=iamra_params,
                    tags={"Purpose": "IAM-Roles-Anywhere", "Component": "IAMRA"},
                )
                click.echo("  Deploy complete.")
            except Exception as e:
                raise click.ClickException(f"IAM RA deployment failed: {e}")
        else:
            click.echo(f"IAM RA stack already exists: {iamra_stack_name}")

    click.echo()
    click.secho("Success!", fg="green", bold=True)
    _show_existing_outputs(rootca_stack_name, iamra_stack_name, region, profile)


def _show_existing_outputs(
    rootca_stack_name: str,
    iamra_stack_name: str,
    region: str,
    profile: Optional[str],
):
    """Show outputs from deployed stacks."""
    click.echo()
    click.echo("Infrastructure outputs:")
    click.echo()

    try:
        rootca_outputs = get_stack_outputs(rootca_stack_name, region, profile)
        click.echo(f"  CA Mode:           {rootca_outputs.get('CAMode', 'N/A')}")
        click.echo(f"  CA Certificate:    (stored in SSM)")
    except Exception:
        click.echo("  Root CA: Unable to retrieve outputs")

    try:
        iamra_outputs = get_stack_outputs(iamra_stack_name, region, profile)
        click.echo(f"  Trust Anchor ARN:  {iamra_outputs.get('TrustAnchorArn', 'N/A')}")
        click.echo(
            f"  Cert Issuer ARN:   {iamra_outputs.get('CertificateIssuerArn', 'N/A')}"
        )
    except Exception:
        click.echo("  IAM RA: Unable to retrieve outputs")

    click.echo()
    click.echo("Next steps:")
    click.echo()
    click.echo("  Onboard hosts with:")
    click.echo("    iam-ra onboard <hostname>")
    click.echo()
