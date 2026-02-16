"""Workflows layer - orchestrate operations into user intents."""

from iam_ra_cli.workflows.ca import delete_scope, list_cas, setup_ca
from iam_ra_cli.workflows.destroy import destroy
from iam_ra_cli.workflows.host import list_hosts, offboard, onboard
from iam_ra_cli.workflows.init import init
from iam_ra_cli.workflows.role import create_role, delete_role, list_roles
from iam_ra_cli.workflows.status import get_status

__all__ = [
    "init",
    "destroy",
    "setup_ca",
    "delete_scope",
    "list_cas",
    "create_role",
    "delete_role",
    "list_roles",
    "onboard",
    "offboard",
    "list_hosts",
    "get_status",
]
