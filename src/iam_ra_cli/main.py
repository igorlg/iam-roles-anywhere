"""IAM Roles Anywhere CLI entry point.

NOTE: The commands layer is a work-in-progress. The underlying workflows/
and operations/ layers are complete and tested. This CLI entry point
provides a minimal interface until the commands are fully wired up.
"""

import click

from . import __version__


@click.group()
@click.version_option(version=__version__, prog_name="iam-ra")
def cli():
    """IAM Roles Anywhere - Certificate-based AWS authentication for Nix hosts."""
    pass


@cli.command()
def status():
    """Show current IAM Roles Anywhere CLI status."""
    click.echo("IAM Roles Anywhere CLI")
    click.echo(f"Version: {__version__}")
    click.echo("")
    click.echo("This CLI is a work-in-progress.")
    click.echo("The underlying workflows and operations are complete and tested.")
    click.echo("")
    click.echo("See docs/cli-design.md for architecture details.")


if __name__ == "__main__":
    cli()
