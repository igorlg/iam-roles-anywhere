"""Migrate command - bring a namespace up to the current schema/layout.

Structured as a Click group so we can expose sub-operations (like
`sops-paths`) for users who want surgical control. Running
`iam-ra migrate` without a subcommand invokes the full upgrade path
(state + CA stacks + SOPS content + SOPS filenames) in one shot.
"""

import click

from iam_ra_cli.commands.common import (
    aws_options,
    echo_key_value,
    handle_result,
    namespace_option,
)
from iam_ra_cli.lib.aws import AwsContext
from iam_ra_cli.workflows.migrate import (
    migrate as migrate_workflow,
)
from iam_ra_cli.workflows.migrate import (
    migrate_sops_paths as migrate_sops_paths_workflow,
)


def _run_full_migrate(namespace: str, region: str, profile: str | None) -> None:
    """Invoke the top-level migrate workflow + pretty-print its result."""
    click.echo(f"Migrating namespace '{namespace}'...")
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

    if result.sops_files_migrated:
        echo_key_value(
            "SOPS files migrated",
            ", ".join(result.sops_files_migrated),
            indent=1,
        )
    else:
        echo_key_value("SOPS files migrated", "none (already v2 or absent)", indent=1)

    if result.sops_paths_renamed:
        echo_key_value(
            "SOPS files renamed",
            ", ".join(result.sops_paths_renamed),
            indent=1,
        )
        click.echo()
        click.echo(
            "  Remember to update any Nix references to the old filename,"
        )
        click.echo("  e.g. sops.secrets.<name>.sopsFile = ./secrets/hosts/<h>/iam-ra.yaml;")
        click.echo("  now becomes  ./secrets/hosts/<h>/iam-ra-default.yaml;")
    else:
        echo_key_value(
            "SOPS files renamed", "none (already canonical or absent)", indent=1
        )

    click.echo()
    click.echo("State is now in the current format with scoped CAs.")
    click.echo(
        "You can use 'iam-ra ca setup --scope <name>' to add per-namespace CAs."
    )


@click.group("migrate", invoke_without_command=True)
@namespace_option
@aws_options
@click.pass_context
def migrate(
    ctx: click.Context,
    namespace: str,
    region: str,
    profile: str | None,
) -> None:
    """Bring a namespace up to the current schema + file layout.

    Without a subcommand, runs the full migration in one shot:

    \b
      1. Converts v1 state JSON to v2 (scoped CAs).
      2. Moves S3 CA cert to scoped path ({ns}/scopes/default/ca/).
      3. Moves local CA key to scoped path.
      4. Updates role CFN stacks with TrustAnchorArn parameter.
      5. Re-saves state (auto-migrated to v3 on save).
      6. Upgrades host SOPS files from v1 YAML to v2 YAML.
      7. Renames legacy iam-ra.yaml -> iam-ra-<namespace>.yaml.

    Safe to run multiple times (idempotent at each step).

    Use subcommands for surgical control:
      iam-ra migrate sops-paths   Only rename legacy filenames.

    \b
    Examples:
      iam-ra migrate
      iam-ra migrate --namespace prod
      iam-ra migrate sops-paths --dry-run
    """
    # Stash the common options on ctx so subcommands can access them.
    ctx.ensure_object(dict)
    ctx.obj["namespace"] = namespace
    ctx.obj["region"] = region
    ctx.obj["profile"] = profile

    if ctx.invoked_subcommand is None:
        _run_full_migrate(namespace, region, profile)


@migrate.command("sops-paths")
@click.option(
    "--dry-run",
    is_flag=True,
    help="Show what would be renamed without touching any files.",
)
@click.pass_context
def migrate_sops_paths_cmd(ctx: click.Context, dry_run: bool) -> None:
    """Rename legacy iam-ra.yaml -> iam-ra-<namespace>.yaml.

    Only applies to the default namespace (non-default namespaces
    never had a legacy filename). If any host has BOTH a legacy and
    a canonical file present, the migration aborts with a clear
    error listing those hosts - resolve manually and rerun.

    \b
    Examples:
      iam-ra migrate sops-paths              # Rename in place.
      iam-ra migrate sops-paths --dry-run    # Preview without renaming.
    """
    namespace = ctx.obj["namespace"]
    region = ctx.obj["region"]
    profile = ctx.obj["profile"]

    if dry_run:
        click.echo(f"Dry-run: SOPS path migration for namespace '{namespace}'")
    else:
        click.echo(f"Renaming legacy SOPS files for namespace '{namespace}'")
    click.echo()

    aws_ctx = AwsContext(region=region, profile=profile)
    result = handle_result(
        migrate_sops_paths_workflow(aws_ctx, namespace, dry_run=dry_run),
        success_message=None,
    )

    if dry_run:
        if result.would_rename:
            click.echo("  Would rename the legacy SOPS file for these hosts:")
            for hostname in result.would_rename:
                click.echo(f"    - {hostname}: iam-ra.yaml -> iam-ra-{namespace}.yaml")
            click.echo()
            click.echo("  Run without --dry-run to apply.")
        else:
            click.echo("  Nothing to rename - no legacy SOPS files found.")
    else:
        if result.renamed:
            click.echo("  Renamed legacy SOPS files for:")
            for hostname in result.renamed:
                click.echo(f"    - {hostname}")
            click.echo()
            click.echo(
                "  Remember to update any Nix references to the old filename,"
            )
            click.echo(
                "  e.g. sops.secrets.<name>.sopsFile = ./secrets/hosts/<h>/iam-ra.yaml;"
            )
            click.echo(
                f"  now becomes  ./secrets/hosts/<h>/iam-ra-{namespace}.yaml;"
            )
        else:
            click.echo("  Nothing renamed - no legacy SOPS files found.")
