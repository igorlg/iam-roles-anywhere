"""Migrate command - convert v1 state to v2 scoped CAs."""

import click

from iam_ra_cli.commands.common import (
    aws_options,
    echo_key_value,
    handle_result,
    namespace_option,
)
from iam_ra_cli.lib.aws import AwsContext
from iam_ra_cli.workflows.migrate import migrate as migrate_workflow


@click.command("migrate")
@namespace_option
@aws_options
def migrate(
    namespace: str,
    region: str,
    profile: str | None,
) -> None:
    """Migrate v1 state to v2 (scoped CAs).

    Converts a single-CA setup to the new scoped CA architecture.
    This moves CA certificates, private keys, and updates role stacks.

    Safe to run multiple times (idempotent).

    \b
    What it does:
      1. Converts state JSON from v1 to v2 format
      2. Moves S3 CA cert to scoped path ({ns}/scopes/default/ca/)
      3. Moves local CA key to scoped path
      4. Updates role CFN stacks with TrustAnchorArn parameter
      5. Re-saves state in v2 format

    \b
    Examples:
      iam-ra migrate
      iam-ra migrate --namespace prod
    """
    click.echo(f"Migrating namespace '{namespace}' from v1 to v2...")
    click.echo()

    ctx = AwsContext(region=region, profile=profile)

    result = handle_result(
        migrate_workflow(ctx, namespace),
        success_message="Migration complete!",
    )

    click.echo()
    if result.s3_migrated:
        echo_key_value("S3 CA cert", "moved to scoped path", indent=1)
    else:
        echo_key_value("S3 CA cert", "already at scoped path (skipped)", indent=1)

    if result.local_key_migrated:
        echo_key_value("Local CA key", "moved to scoped path", indent=1)
    else:
        echo_key_value("Local CA key", "already at scoped path (skipped)", indent=1)

    if result.roles_updated:
        echo_key_value("Roles updated", ", ".join(result.roles_updated), indent=1)
    else:
        echo_key_value("Roles updated", "none", indent=1)

    click.echo()
    click.echo("State is now in v2 format with scoped CAs.")
    click.echo("You can now use 'iam-ra ca setup --scope <name>' to add per-namespace CAs.")
