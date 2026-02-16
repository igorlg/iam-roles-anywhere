"""Commands layer - CLI facade over workflows."""

from iam_ra_cli.commands.ca import ca
from iam_ra_cli.commands.destroy import destroy
from iam_ra_cli.commands.host import host
from iam_ra_cli.commands.init import init
from iam_ra_cli.commands.k8s import k8s
from iam_ra_cli.commands.migrate import migrate
from iam_ra_cli.commands.role import role
from iam_ra_cli.commands.status import status

__all__ = [
    "init",
    "destroy",
    "status",
    "ca",
    "role",
    "host",
    "k8s",
    "migrate",
]
