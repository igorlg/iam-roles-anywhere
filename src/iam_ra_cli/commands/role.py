"""Role commands - create, list, delete IAM roles with Roles Anywhere profiles."""

import click

from iam_ra_cli.lib import cfn, state
from iam_ra_cli.lib.templates import get_template_path
from iam_ra_cli.models import Arn, Role


ROLE_TEMPLATE = "role.yaml"

DEFAULT_NAMESPACE = "default"
DEFAULT_REGION = "ap-southeast-2"


def _stack_name(namespace: str, role_name: str) -> str:
    """Generate stack name for a role."""
    return f"iam-ra-{namespace}-role-{role_name}"


def _load_template(name: str) -> str:
    """Load CloudFormation template body."""
    path = get_template_path(name)
    return path.read_text()


def _require_initialized(namespace: str, region: str, profile: str | None) -> state.State:
    """Load state and ensure namespace is initialized."""
    from iam_ra_cli.models import State

    current = state.load(namespace, region, profile)
    if current is None or not current.is_initialized:
        raise click.ClickException(
            f"Namespace '{namespace}' is not initialized. Run 'iam-ra init' first."
        )
    return current


@click.group()
def role() -> None:
    """Manage IAM roles for Roles Anywhere."""
    pass


@role.command("create")
@click.argument("name")
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
    "--policies",
    multiple=True,
    help="Managed policy ARNs to attach (can specify multiple times)",
)
@click.option(
    "--session-duration",
    default=3600,
    show_default=True,
    help="Session duration in seconds (900-43200)",
)
def create(
    name: str,
    namespace: str,
    region: str,
    profile: str | None,
    policies: tuple[str, ...],
    session_duration: int,
) -> None:
    """Create an IAM role with Roles Anywhere profile.

    NAME is the logical name for this role (used in stack naming and references).

    \b
    Examples:
      iam-ra role create admin --policies arn:aws:iam::aws:policy/AdministratorAccess
      iam-ra role create readonly --policies arn:aws:iam::aws:policy/ReadOnlyAccess
      iam-ra role create dev --policies arn:aws:iam::123:policy/DevPolicy --session-duration 7200
    """
    current = _require_initialized(namespace, region, profile)
    assert current.ca is not None

    # Check if role already exists
    if name in current.roles:
        existing = current.roles[name]
        click.echo(f"Role '{name}' already exists:")
        click.echo(f"  Stack:   {existing.stack_name}")
        click.echo(f"  Role:    {existing.role_arn}")
        click.echo(f"  Profile: {existing.profile_arn}")
        return

    click.echo(f"Creating role: {name}")
    click.echo(f"  Namespace: {namespace}")
    click.echo(f"  Policies:  {len(policies)} attached")
    click.echo()

    stack = _stack_name(namespace, name)
    template = _load_template(ROLE_TEMPLATE)

    # Build parameters
    params: dict[str, str] = {
        "Namespace": namespace,
        "RoleName": name,
        "TrustAnchorArn": str(current.ca.trust_anchor_arn),
        "SessionDuration": str(session_duration),
    }
    if policies:
        params["PolicyArns"] = ",".join(policies)

    click.echo(f"Deploying stack: {stack}")
    outputs = cfn.deploy(
        stack_name=stack,
        template_body=template,
        region=region,
        profile=profile,
        parameters=params,
        tags={"iam-ra:namespace": namespace, "iam-ra:role": name},
        capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    )

    role_arn = Arn(outputs["RoleArn"])
    profile_arn = Arn(outputs["ProfileArn"])

    click.echo(f"  Role ARN:    {role_arn}")
    click.echo(f"  Profile ARN: {profile_arn}")

    # Update state
    new_role = Role(
        stack_name=stack,
        role_arn=role_arn,
        profile_arn=profile_arn,
        policies=tuple(Arn(p) for p in policies),
    )
    current.roles[name] = new_role
    state.save(current, region, profile)

    click.echo()
    click.secho(f"Role '{name}' created successfully!", fg="green", bold=True)


@role.command("list")
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
def list_roles(
    namespace: str,
    region: str,
    profile: str | None,
) -> None:
    """List all roles in the namespace."""
    current = _require_initialized(namespace, region, profile)

    if not current.roles:
        click.echo(f"No roles in namespace '{namespace}'")
        click.echo()
        click.echo("Create one with: iam-ra role create <name> --policies <arn>")
        return

    click.echo(f"Roles in namespace '{namespace}':")
    click.echo()
    for name, r in sorted(current.roles.items()):
        click.echo(f"  {name}")
        click.echo(f"    Role:     {r.role_arn}")
        click.echo(f"    Profile:  {r.profile_arn}")
        if r.policies:
            click.echo(f"    Policies: {len(r.policies)}")
        click.echo()


@role.command("delete")
@click.argument("name")
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
    "--force",
    is_flag=True,
    help="Delete even if hosts are using this role",
)
def delete(
    name: str,
    namespace: str,
    region: str,
    profile: str | None,
    force: bool,
) -> None:
    """Delete an IAM role and its Roles Anywhere profile.

    NAME is the logical name of the role to delete.
    """
    current = _require_initialized(namespace, region, profile)

    if name not in current.roles:
        raise click.ClickException(f"Role '{name}' not found in namespace '{namespace}'")

    # Check if any hosts are using this role
    hosts_using = [h for h, host in current.hosts.items() if host.role_name == name]
    if hosts_using and not force:
        click.echo(f"Cannot delete role '{name}' - used by hosts:")
        for h in hosts_using:
            click.echo(f"  - {h}")
        click.echo()
        click.echo("Use --force to delete anyway, or offboard the hosts first.")
        return

    existing = current.roles[name]
    click.echo(f"Deleting role: {name}")
    click.echo(f"  Stack: {existing.stack_name}")
    click.echo()

    cfn.delete(existing.stack_name, region, profile)

    # Update state
    del current.roles[name]
    state.save(current, region, profile)

    click.echo()
    click.secho(f"Role '{name}' deleted successfully!", fg="green", bold=True)
