"""Migrate workflow - convert v1 state to v2 scoped CAs.

Handles all aspects of migration:
1. State JSON: auto-migrated by State.from_json(), re-saved in v2 format
2. S3 paths: copy CA cert from old to scoped path, delete old
3. Local paths: move CA private key from old to scoped path
4. Role CFN stacks: update with new template (adds TrustAnchorArn param)

Idempotent: safe to run multiple times. Skips already-migrated paths.
"""

from dataclasses import dataclass, field

from iam_ra_cli.lib import paths, state as state_module
from iam_ra_cli.lib.aws import AwsContext
from iam_ra_cli.lib.errors import (
    NotInitializedError,
    StackDeployError,
    StateLoadError,
    StateSaveError,
)
from iam_ra_cli.lib.result import Err, Ok, Result
from iam_ra_cli.lib.storage.s3 import delete_object, object_exists, read_object, write_object
from iam_ra_cli.operations.ca import _ca_cert_s3_key, _ca_key_local_path
from iam_ra_cli.operations.role import create_role as create_role_op

# =============================================================================
# Error / Result Types
# =============================================================================

type MigrateError = NotInitializedError | StateLoadError | StateSaveError | StackDeployError


@dataclass(frozen=True)
class MigrateResult:
    """Result of migration."""

    s3_migrated: bool = False
    local_key_migrated: bool = False
    roles_updated: list[str] = field(default_factory=list)


# =============================================================================
# Helpers
# =============================================================================


def _old_ca_cert_s3_key(namespace: str) -> str:
    """v1 S3 path for CA certificate."""
    return f"{namespace}/ca/certificate.pem"


def _old_ca_key_local_path(namespace: str):
    """v1 local path for CA private key."""
    return paths.data_dir() / namespace / "ca-private-key.pem"


def update_role_stack(
    ctx: AwsContext,
    namespace: str,
    name: str,
    trust_anchor_arn: str,
    policies: list[str],
    scope: str,
) -> Result[None, StackDeployError]:
    """Update a role's CFN stack with the v2 template (adds TrustAnchorArn param).

    This is a thin wrapper around operations/role.create_role which is
    idempotent (CFN stack update).
    """
    match create_role_op(
        ctx,
        namespace=namespace,
        name=name,
        policies=policies if policies else None,
        trust_anchor_arn=trust_anchor_arn,
        scope=scope,
    ):
        case Err() as e:
            return e
        case Ok(_):
            return Ok(None)


# =============================================================================
# Main Workflow
# =============================================================================


def migrate(ctx: AwsContext, namespace: str) -> Result[MigrateResult, MigrateError]:
    """Migrate v1 state to v2 (scoped CAs).

    Steps:
    1. Load state (from_json auto-migrates v1 -> v2)
    2. Move S3 CA cert to scoped path (if old path exists)
    3. Move local CA key to scoped path (if old path exists)
    4. Update role CFN stacks with TrustAnchorArn parameter
    5. Re-save state in v2 format

    Idempotent: safe to run multiple times.
    """
    # 1. Load state (auto-migrates v1 JSON to v2 in-memory)
    match state_module.load(ctx.ssm, ctx.s3, namespace, skip_cache=True):
        case Err(e):
            return Err(e)
        case Ok(None):
            return Err(NotInitializedError(namespace))
        case Ok(state):
            pass

    if not state.is_initialized:
        return Err(NotInitializedError(namespace))

    assert state.init is not None

    bucket_name = state.init.bucket_arn.resource_id
    s3_migrated = False
    local_key_migrated = False
    roles_updated: list[str] = []

    # 2. Migrate S3 CA cert: old path -> scoped path
    old_s3_key = _old_ca_cert_s3_key(namespace)
    new_s3_key = _ca_cert_s3_key(namespace, "default")

    if object_exists(ctx.s3, bucket_name, old_s3_key):
        # Read from old path
        match read_object(ctx.s3, bucket_name, old_s3_key):
            case Err(e):
                return Err(StateSaveError(namespace, f"Failed to read old CA cert: {e}"))
            case Ok(cert_pem):
                pass

        # Write to new scoped path
        match write_object(ctx.s3, bucket_name, new_s3_key, cert_pem):
            case Err(e):
                return Err(StateSaveError(namespace, f"Failed to write scoped CA cert: {e}"))
            case Ok(_):
                pass

        # Delete old path
        delete_object(ctx.s3, bucket_name, old_s3_key)
        s3_migrated = True

    # 3. Migrate local CA key: old path -> scoped path
    old_key_path = _old_ca_key_local_path(namespace)
    new_key_path = _ca_key_local_path(namespace, "default")

    if old_key_path.exists():
        # Read old key
        key_pem = old_key_path.read_text()

        # Write to new scoped path
        new_key_path.parent.mkdir(parents=True, exist_ok=True)
        new_key_path.write_text(key_pem)
        new_key_path.chmod(0o600)

        # Delete old key
        old_key_path.unlink()
        local_key_migrated = True

    # 4. Update role CFN stacks with TrustAnchorArn parameter
    if "default" in state.cas:
        default_ca = state.cas["default"]
        trust_anchor_arn = str(default_ca.trust_anchor_arn)

        for role_name, role in state.roles.items():
            policies = [str(p) for p in role.policies]
            match update_role_stack(
                ctx,
                namespace=namespace,
                name=role_name,
                trust_anchor_arn=trust_anchor_arn,
                policies=policies,
                scope=role.scope,
            ):
                case Err() as e:
                    return e
                case Ok(_):
                    roles_updated.append(role_name)

    # 5. Re-save state in v2 format
    match state_module.save(ctx.ssm, ctx.s3, state):
        case Err() as e:
            return e
        case Ok(_):
            pass

    return Ok(
        MigrateResult(
            s3_migrated=s3_migrated,
            local_key_migrated=local_key_migrated,
            roles_updated=roles_updated,
        )
    )
