"""Status command - show current IAM Roles Anywhere status."""

import click

from iam_ra_cli.commands.common import (
    aws_options,
    echo_key_value,
    echo_section,
    json_option,
    make_context,
    namespace_option,
    to_json,
)
from iam_ra_cli.workflows import get_status


@click.command()
@namespace_option
@aws_options
@json_option
def status(
    namespace: str,
    region: str,
    profile: str | None,
    as_json: bool,
) -> None:
    """Show current IAM Roles Anywhere status.

    Displays initialization status, CA configuration, roles, and hosts.

    \b
    Examples:
      iam-ra status
      iam-ra status --namespace prod
      iam-ra status --json
    """
    ctx = make_context(region, profile)
    current = get_status(ctx, namespace)

    if as_json:
        click.echo(to_json(current))
        return

    # Human-readable output
    click.echo("IAM Roles Anywhere Status")
    click.echo("=" * 40)
    echo_key_value("Namespace", current.namespace)
    echo_key_value("Region", current.region)
    echo_key_value("Initialized", "Yes" if current.initialized else "No")

    if not current.initialized:
        click.echo()
        click.echo("Run 'iam-ra init' to initialize.")
        return

    # Init info
    if current.init:
        echo_section("Infrastructure")
        echo_key_value("Stack", current.init.stack_name, indent=1)
        echo_key_value("Bucket", current.init.bucket_arn.resource_id, indent=1)
        echo_key_value("KMS Key", str(current.init.kms_key_arn), indent=1)

    # CA info
    if current.cas:
        echo_section(f"Certificate Authorities ({len(current.cas)})")
        for scope_name, ca in sorted(current.cas.items()):
            click.echo(f"  [{scope_name}]")
            echo_key_value("Stack", ca.stack_name, indent=2)
            echo_key_value("Mode", ca.mode.value, indent=2)
            echo_key_value("Trust Anchor", str(ca.trust_anchor_arn), indent=2)
            if ca.pca_arn:
                echo_key_value("PCA ARN", str(ca.pca_arn), indent=2)

    # Roles
    echo_section(f"Roles ({len(current.roles)})")
    if current.roles:
        for name, role in sorted(current.roles.items()):
            click.echo(f"  {name}")
            echo_key_value("Role ARN", str(role.role_arn), indent=2)
            echo_key_value("Profile ARN", str(role.profile_arn), indent=2)
            if role.policies:
                echo_key_value("Policies", len(role.policies), indent=2)
    else:
        click.echo("  (none)")

    # Hosts
    echo_section(f"Hosts ({len(current.hosts)})")
    if current.hosts:
        for hostname, host in sorted(current.hosts.items()):
            click.echo(f"  {hostname}")
            echo_key_value("Role", host.role_name, indent=2)
            echo_key_value("Stack", host.stack_name, indent=2)
    else:
        click.echo("  (none)")

    click.echo()
