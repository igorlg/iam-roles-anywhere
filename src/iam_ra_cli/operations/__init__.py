"""Operations layer - atomic operations that return Result types."""

from iam_ra_cli.operations.ca import (
    attach_existing_pca,
    create_pca_ca,
    create_self_signed_ca,
    delete_ca,
)
from iam_ra_cli.operations.host import (
    offboard_host,
    onboard_host_pca,
    onboard_host_self_signed,
)
from iam_ra_cli.operations.infra import delete_init, deploy_init
from iam_ra_cli.operations.role import create_role, delete_role
from iam_ra_cli.operations.secrets import create_secrets_file

__all__ = [
    # infra
    "deploy_init",
    "delete_init",
    # ca
    "create_self_signed_ca",
    "create_pca_ca",
    "attach_existing_pca",
    "delete_ca",
    # role
    "create_role",
    "delete_role",
    # host
    "onboard_host_self_signed",
    "onboard_host_pca",
    "offboard_host",
    # secrets
    "create_secrets_file",
]
