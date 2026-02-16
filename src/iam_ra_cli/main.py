"""IAM Roles Anywhere CLI entry point."""

import click

from . import __version__
from .commands import ca, destroy, host, init, k8s, migrate, role, status


@click.group()
@click.version_option(version=__version__, prog_name="iam-ra")
def cli() -> None:
    """IAM Roles Anywhere - Certificate-based AWS authentication for Nix hosts."""
    pass


# Register commands
cli.add_command(init)
cli.add_command(destroy)
cli.add_command(status)
cli.add_command(ca)
cli.add_command(role)
cli.add_command(host)
cli.add_command(k8s)
cli.add_command(migrate)


if __name__ == "__main__":
    cli()
