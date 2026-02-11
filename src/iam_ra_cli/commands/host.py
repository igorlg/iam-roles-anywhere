"""Host commands - manage hosts for Roles Anywhere."""

from pathlib import Path

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
from iam_ra_cli.workflows import list_hosts, offboard, onboard
from iam_ra_cli.workflows.host import OnboardConfig


@click.group()
def host() -> None:
    """Manage hosts for Roles Anywhere."""
    pass


@host.command("onboard")
@click.argument("hostname")
@click.option(
    "--role",
    "-R",
    "role_name",
    required=True,
    help="Role name to associate with this host (must exist)",
)
@namespace_option
@aws_options
@click.option(
    "--validity-days",
    default=365,
    show_default=True,
    help="Certificate validity in days",
)
@click.option(
    "--no-sops",
    is_flag=True,
    help="Skip creating SOPS-encrypted secrets file",
)
@click.option(
    "--sops-output",
    type=click.Path(),
    default=None,
    help="Custom output path for SOPS file",
)
@click.option(
    "--overwrite",
    is_flag=True,
    help="Overwrite existing host/secrets",
)
def host_onboard(
    hostname: str,
    role_name: str,
    namespace: str,
    region: str,
    profile: str | None,
    validity_days: int,
    no_sops: bool,
    sops_output: str | None,
    overwrite: bool,
) -> None:
    """Onboard a host to IAM Roles Anywhere.

    Generates a host certificate, stores it in Secrets Manager, and
    optionally creates a SOPS-encrypted secrets file for Nix deployment.

    HOSTNAME is the identifier for this host (used in certificate CN).

    \b
    Examples:
      iam-ra host onboard myhost --role admin
      iam-ra host onboard myhost --role readonly --validity-days 90
      iam-ra host onboard webserver --role app --no-sops
    """
    click.echo(f"Onboarding host: {hostname}")
    echo_key_value("Namespace", namespace, indent=1)
    echo_key_value("Role", role_name, indent=1)
    echo_key_value("Validity", f"{validity_days} days", indent=1)
    click.echo()

    ctx = make_context(region, profile)
    config = OnboardConfig(
        namespace=namespace,
        hostname=hostname,
        role_name=role_name,
        validity_days=validity_days,
        create_sops=not no_sops,
        sops_output_path=Path(sops_output) if sops_output else None,
        overwrite=overwrite,
    )

    click.echo("[1/3] Generating host certificate...")
    click.echo("[2/3] Deploying host stack...")
    if not no_sops:
        click.echo("[3/3] Creating SOPS secrets file...")

    result = handle_result(
        onboard(ctx, config),
        success_message=f"Host '{hostname}' onboarded successfully!",
    )

    click.echo()
    echo_key_value("Certificate secret", str(result.host.certificate_secret_arn), indent=1)
    echo_key_value("Private key secret", str(result.host.private_key_secret_arn), indent=1)

    if result.secrets_file:
        click.echo()
        echo_key_value("SOPS file", str(result.secrets_file.path), indent=1)

    click.echo()
    click.echo("Next steps:")
    click.echo()
    click.echo(f"1. Add to your Nix host configuration ({hostname}):")
    click.echo()
    click.echo("   programs.iamRolesAnywhere = {")
    click.echo("     enable = true;")
    click.echo('     secretsPath = "/path/to/secrets";')
    click.echo("   };")
    click.echo()
    click.echo("2. Deploy and verify:")
    click.echo()
    click.echo("   aws sts get-caller-identity --profile iam-ra")


@host.command("offboard")
@click.argument("hostname")
@namespace_option
@aws_options
def host_offboard(
    hostname: str,
    namespace: str,
    region: str,
    profile: str | None,
) -> None:
    """Offboard a host from IAM Roles Anywhere.

    Deletes the host stack and cleans up S3 artifacts.
    Does NOT delete local SOPS files.

    HOSTNAME is the identifier of the host to offboard.

    \b
    Examples:
      iam-ra host offboard myhost
      iam-ra host offboard webserver --namespace prod
    """
    click.echo(f"Offboarding host: {hostname}")

    ctx = make_context(region, profile)

    handle_result(
        offboard(ctx, namespace, hostname),
        success_message=f"Host '{hostname}' offboarded successfully!",
    )


@host.command("list")
@namespace_option
@aws_options
@json_option
def host_list(
    namespace: str,
    region: str,
    profile: str | None,
    as_json: bool,
) -> None:
    """List all hosts in the namespace.

    \b
    Examples:
      iam-ra host list
      iam-ra host list --namespace prod
      iam-ra host list --json
    """
    ctx = make_context(region, profile)

    hosts = handle_result(list_hosts(ctx, namespace))

    if as_json:
        click.echo(to_json(hosts))
        return

    if not hosts:
        click.echo(f"No hosts in namespace '{namespace}'")
        click.echo()
        click.echo("Onboard one with: iam-ra host onboard <hostname> --role <name>")
        return

    click.echo(f"Hosts in namespace '{namespace}':")
    click.echo()
    for hostname, h in sorted(hosts.items()):
        click.echo(f"  {hostname}")
        echo_key_value("Role", h.role_name, indent=2)
        echo_key_value("Stack", h.stack_name, indent=2)
        click.echo()
