"""Init command - initialize IAM Roles Anywhere infrastructure."""

import click

from iam_ra_cli.commands.common import (
    aws_options,
    echo_key_value,
    handle_result,
    make_context,
    namespace_option,
)
from iam_ra_cli.models import CAMode
from iam_ra_cli.workflows import init as init_workflow
from iam_ra_cli.workflows.init import InitConfig


@click.command()
@namespace_option
@aws_options
@click.option(
    "--ca-mode",
    type=click.Choice(["self-signed", "pca-new", "pca-existing"]),
    default="self-signed",
    show_default=True,
    help="Certificate Authority mode",
)
@click.option(
    "--pca-arn",
    default=None,
    help="Existing ACM PCA ARN (required for pca-existing mode)",
)
@click.option(
    "--ca-validity-years",
    default=10,
    show_default=True,
    help="CA certificate validity in years",
)
def init(
    namespace: str,
    region: str,
    profile: str | None,
    ca_mode: str,
    pca_arn: str | None,
    ca_validity_years: int,
) -> None:
    """Initialize IAM Roles Anywhere infrastructure.

    Deploys the init stack (S3, KMS, Lambdas) and CA stack (Trust Anchor).

    \b
    CA Modes:
      self-signed   - Generate a self-signed CA locally (default, simplest)
      pca-new       - Create a new AWS Private CA
      pca-existing  - Use an existing AWS Private CA (requires --pca-arn)

    \b
    Examples:
      iam-ra init
      iam-ra init --namespace prod --region us-east-1
      iam-ra init --ca-mode pca-existing --pca-arn arn:aws:acm-pca:...
    """
    # Validate options
    mode = CAMode(ca_mode)
    if mode == CAMode.PCA_EXISTING and not pca_arn:
        raise click.ClickException("--pca-arn required for pca-existing mode")

    click.echo("Initializing IAM Roles Anywhere")
    echo_key_value("Namespace", namespace, indent=1)
    echo_key_value("Region", region, indent=1)
    echo_key_value("CA mode", ca_mode, indent=1)
    click.echo()

    ctx = make_context(region, profile)
    config = InitConfig(
        namespace=namespace,
        ca_mode=mode,
        pca_arn=pca_arn,
        ca_validity_years=ca_validity_years,
    )

    click.echo("[1/2] Deploying init stack...")
    click.echo("[2/2] Deploying CA stack...")

    state = handle_result(
        init_workflow(ctx, config),
        success_message="Initialization complete!",
    )

    click.echo()
    if state.init:
        echo_key_value("Bucket", state.init.bucket_arn.resource_id, indent=1)
        echo_key_value("KMS Key", str(state.init.kms_key_arn), indent=1)
    if state.ca:
        echo_key_value("Trust Anchor", str(state.ca.trust_anchor_arn), indent=1)

    click.echo()
    click.echo("Next steps:")
    click.echo("  1. Create a role:  iam-ra role create <name> --policy <arn>")
    click.echo("  2. Onboard hosts:  iam-ra host onboard <hostname> --role <name>")
