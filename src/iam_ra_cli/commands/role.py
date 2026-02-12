"""Role commands - manage IAM roles for Roles Anywhere."""

import click

from iam_ra_cli.commands.common import (
    aws_options,
    echo_key_value,
    handle_result,
    json_option,
    make_context,
    namespace_option,
    to_json,
)
from iam_ra_cli.workflows import create_role, delete_role, list_roles


@click.group()
def role() -> None:
    """Manage IAM roles for Roles Anywhere."""
    pass


@role.command("create")
@click.argument("name")
@namespace_option
@aws_options
@click.option(
    "--policy",
    "policies",
    multiple=True,
    help="Managed policy ARN to attach (can specify multiple times)",
)
@click.option(
    "--session-duration",
    default=3600,
    show_default=True,
    help="Session duration in seconds (900-43200)",
)
def role_create(
    name: str,
    namespace: str,
    region: str,
    profile: str | None,
    policies: tuple[str, ...],
    session_duration: int,
) -> None:
    """Create an IAM role with Roles Anywhere profile.

    NAME is the logical name for this role.

    \b
    Examples:
      iam-ra role create admin --policy arn:aws:iam::aws:policy/AdministratorAccess
      iam-ra role create readonly --policy arn:aws:iam::aws:policy/ReadOnlyAccess
      iam-ra role create dev --policy arn:aws:iam::123:policy/DevPolicy --session-duration 7200
    """
    click.echo(f"Creating role: {name}")
    echo_key_value("Namespace", namespace, indent=1)
    echo_key_value("Policies", len(policies), indent=1)
    echo_key_value("Session duration", f"{session_duration}s", indent=1)
    click.echo()

    ctx = make_context(region, profile)

    new_role = handle_result(
        create_role(ctx, namespace, name, list(policies) if policies else None, session_duration),
        success_message=f"Role '{name}' ready!",
    )

    click.echo()
    echo_key_value("Role ARN", str(new_role.role_arn), indent=1)
    echo_key_value("Profile ARN", str(new_role.profile_arn), indent=1)

    click.echo()
    click.echo("Next step:")
    click.echo(f"  Onboard a host: iam-ra host onboard <hostname> --role {name}")


@role.command("delete")
@click.argument("name")
@namespace_option
@aws_options
@click.option(
    "--force",
    is_flag=True,
    help="Delete even if hosts are using this role",
)
def role_delete(
    name: str,
    namespace: str,
    region: str,
    profile: str | None,
    force: bool,
) -> None:
    """Delete an IAM role and its Roles Anywhere profile.

    NAME is the logical name of the role to delete.

    \b
    Examples:
      iam-ra role delete dev
      iam-ra role delete admin --force
    """
    click.echo(f"Deleting role: {name}")

    ctx = make_context(region, profile)

    handle_result(
        delete_role(ctx, namespace, name, force),
        success_message=f"Role '{name}' deleted successfully!",
    )


@role.command("list")
@namespace_option
@aws_options
@json_option
def role_list(
    namespace: str,
    region: str,
    profile: str | None,
    as_json: bool,
) -> None:
    """List all roles in the namespace.

    \b
    Examples:
      iam-ra role list
      iam-ra role list --namespace prod
      iam-ra role list --json
    """
    ctx = make_context(region, profile)

    roles = handle_result(list_roles(ctx, namespace))

    if as_json:
        click.echo(to_json(roles))
        return

    if not roles:
        click.echo(f"No roles in namespace '{namespace}'")
        click.echo()
        click.echo("Create one with: iam-ra role create <name> --policy <arn>")
        return

    click.echo(f"Roles in namespace '{namespace}':")
    click.echo()
    for name, r in sorted(roles.items()):
        click.echo(f"  {name}")
        echo_key_value("Role ARN", str(r.role_arn), indent=2)
        echo_key_value("Profile ARN", str(r.profile_arn), indent=2)
        if r.policies:
            echo_key_value("Policies", len(r.policies), indent=2)
        click.echo()
