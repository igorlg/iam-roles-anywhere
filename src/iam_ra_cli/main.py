"""IAM Roles Anywhere CLI entry point."""

import click

from . import __version__
from .commands.onboard import onboard
from .commands.init import init


@click.group()
@click.version_option(version=__version__, prog_name="iam-ra")
def cli():
    """IAM Roles Anywhere - Certificate-based AWS authentication for Nix hosts."""
    pass


@cli.command()
def status():
    """Show current IAM Roles Anywhere configuration status."""
    click.echo("IAM Roles Anywhere CLI")
    click.echo(f"Version: {__version__}")
    click.echo("")
    click.echo("Commands available:")
    click.echo("  iam-ra init      - Initialize IAM Roles Anywhere infrastructure")
    click.echo("  iam-ra onboard   - Onboard a host (deploy stack + fetch secrets)")
    click.echo("  iam-ra status    - Show this status")


# Register subcommands
cli.add_command(init)
cli.add_command(onboard)


if __name__ == "__main__":
    cli()
