"""Commands layer - CLI facade over workflows."""

from iam_ra_cli.commands.destroy import destroy
from iam_ra_cli.commands.host import host
from iam_ra_cli.commands.init import init
from iam_ra_cli.commands.role import role
from iam_ra_cli.commands.status import status

__all__ = [
    "init",
    "destroy",
    "status",
    "role",
    "host",
]
