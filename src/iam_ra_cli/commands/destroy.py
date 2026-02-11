"""Destroy command - tear down IAM Roles Anywhere infrastructure."""

import click

from iam_ra_cli.commands.common import (
    aws_options,
    handle_result,
    make_context,
    namespace_option,
)
from iam_ra_cli.workflows import destroy as destroy_workflow


@click.command()
@namespace_option
@aws_options
@click.option(
    "--yes",
    is_flag=True,
    help="Skip confirmation prompt",
)
def destroy(
    namespace: str,
    region: str,
    profile: str | None,
    yes: bool,
) -> None:
    """Tear down all IAM Roles Anywhere infrastructure.

    Deletes all resources in order:
    1. All host stacks
    2. All role stacks
    3. CA stack
    4. Init stack (empties and deletes S3 bucket)

    \b
    Examples:
      iam-ra destroy
      iam-ra destroy --namespace prod --yes
    """
    if not yes:
        click.echo(f"This will destroy ALL resources in namespace '{namespace}':")
        click.echo("  - All host certificates and stacks")
        click.echo("  - All role stacks")
        click.echo("  - CA and Trust Anchor")
        click.echo("  - S3 bucket and KMS key")
        click.echo()
        if not click.confirm("Are you sure you want to continue?"):
            click.echo("Aborted.")
            return

    click.echo(f"Destroying namespace '{namespace}'...")
    click.echo()

    ctx = make_context(region, profile)

    handle_result(
        destroy_workflow(ctx, namespace),
        success_message=f"Namespace '{namespace}' destroyed successfully!",
    )
