"""Operations layer - atomic operations that return Result types."""

from iam_ra_cli.operations.ca import (
    attach_existing_pca,
    create_pca_ca,
    create_self_signed_ca,
    delete_ca,
)
from iam_ra_cli.operations.enrol import sign_host_csr
from iam_ra_cli.operations.host import offboard_host
from iam_ra_cli.operations.infra import delete_init, deploy_init
from iam_ra_cli.operations.role import create_role, delete_role

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
    # enrolment
    "sign_host_csr",
    # host teardown (legacy v2/v3 hosts only)
    "offboard_host",
]
