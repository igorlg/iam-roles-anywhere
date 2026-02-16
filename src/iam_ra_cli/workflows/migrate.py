"""Migrate workflow - convert v1 state to v2 scoped CAs.

Handles all aspects of migration:
1. State JSON: auto-migrated by State.from_json(), re-saved in v2 format
2. S3 paths: copy CA cert from old to scoped path, delete old
3. Local paths: move CA private key from old to scoped path
4. CA CFN stacks: create new v2 stack per scope, delete old v1 stack
5. Role CFN stacks: update with new template (adds TrustAnchorArn param)
6. Bump state version to 2.0.0

Idempotent: safe to run multiple times. Skips already-migrated paths/stacks.
"""

from dataclasses import dataclass, field

from iam_ra_cli.lib import paths
from iam_ra_cli.lib import state as state_module
from iam_ra_cli.lib.aws import AwsContext
from iam_ra_cli.lib.cfn import delete_stack, deploy_stack
from iam_ra_cli.lib.errors import (
    NotInitializedError,
    StackDeleteError,
    StackDeployError,
    StateLoadError,
    StateSaveError,
)
from iam_ra_cli.lib.result import Err, Ok, Result
from iam_ra_cli.lib.storage.s3 import delete_object, object_exists, read_object, write_object
from iam_ra_cli.models import CA, Arn
from iam_ra_cli.operations.ca import (
    ROOTCA_SELF_SIGNED_TEMPLATE,
    _ca_cert_s3_key,
    _ca_key_local_path,
    _load_template,
)
from iam_ra_cli.operations.ca import (
    _stack_name as ca_stack_name,
)
from iam_ra_cli.operations.role import create_role as create_role_op

# =============================================================================
# Constants
# =============================================================================

STATE_VERSION_V2 = "2.0.0"

# =============================================================================
# Error / Result Types
# =============================================================================

type MigrateError = (
    NotInitializedError | StateLoadError | StateSaveError | StackDeployError | StackDeleteError
)


@dataclass(frozen=True)
class MigrateResult:
    """Result of migration."""

    s3_migrated: bool = False
    local_key_migrated: bool = False
    ca_stack_migrated: bool = False
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


def migrate_ca_stack(
    ctx: AwsContext,
    namespace: str,
    scope: str,
    old_stack_name: str,
    bucket_name: str,
    trust_anchor_arn: str,
) -> Result[str, StackDeployError | StackDeleteError]:
    """Migrate a CA's CFN stack from v1 to v2.

    Creates a new stack with v2 naming/template, then deletes the old one.
    This avoids in-place updates that would replace the Trust Anchor
    (changing its ARN and invalidating all existing certificates).

    The new stack references the same CA certificate (already at the
    scoped S3 path), so it creates a second Trust Anchor backed by the
    same CA cert. Role stacks are updated separately to reference the
    new Trust Anchor ARN.

    Returns the new Trust Anchor ARN from the new stack.
    """
    new_stack_name = ca_stack_name(namespace, scope)
    cert_s3_key = _ca_cert_s3_key(namespace, scope)

    template = _load_template(ROOTCA_SELF_SIGNED_TEMPLATE)
    match deploy_stack(
        ctx.cfn,
        stack_name=new_stack_name,
        template_body=template,
        parameters={
            "Namespace": namespace,
            "Scope": scope,
            "CACertificateS3Key": cert_s3_key,
        },
        tags={
            "iam-ra:namespace": namespace,
            "iam-ra:scope": scope,
        },
    ):
        case Err() as e:
            return e
        case Ok(outputs):
            new_trust_anchor_arn = outputs["TrustAnchorArn"]

    # New stack is up -- safe to delete the old one
    match delete_stack(ctx.cfn, old_stack_name):
        case Err() as e:
            return e
        case Ok(_):
            pass

    return Ok(new_trust_anchor_arn)


# =============================================================================
# Main Workflow
# =============================================================================


def migrate(ctx: AwsContext, namespace: str) -> Result[MigrateResult, MigrateError]:
    """Migrate v1 state to v2 (scoped CAs).

    Steps:
    1. Load state (from_json auto-migrates v1 -> v2)
    2. Move S3 CA cert to scoped path (if old path exists)
    3. Move local CA key to scoped path (if old path exists)
    4. Migrate CA CFN stacks (create new v2 stack, delete old v1 stack)
    5. Update role CFN stacks with TrustAnchorArn parameter
    6. Bump version to 2.0.0
    7. Re-save state in v2 format

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
    ca_stack_migrated = False
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

    # 4. Migrate CA CFN stacks: create new v2 stack, delete old v1 stack
    for scope, ca in list(state.cas.items()):
        expected_v2_name = ca_stack_name(namespace, scope)
        if ca.stack_name == expected_v2_name:
            continue  # Already migrated

        match migrate_ca_stack(
            ctx,
            namespace=namespace,
            scope=scope,
            old_stack_name=ca.stack_name,
            bucket_name=bucket_name,
            trust_anchor_arn=str(ca.trust_anchor_arn),
        ):
            case Err() as e:
                return e
            case Ok(new_trust_anchor_arn):
                pass

        # Update state with new stack name and new trust anchor ARN
        state.cas[scope] = CA(
            stack_name=expected_v2_name,
            mode=ca.mode,
            trust_anchor_arn=Arn(new_trust_anchor_arn),
            pca_arn=ca.pca_arn,
        )
        ca_stack_migrated = True

    # 5. Update role CFN stacks with TrustAnchorArn parameter
    for role_name, role in state.roles.items():
        scope = role.scope
        if scope not in state.cas:
            continue  # skip roles whose scope CA doesn't exist yet

        scope_ca = state.cas[scope]
        trust_anchor_arn = str(scope_ca.trust_anchor_arn)
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

    # 6. Bump version
    state.version = STATE_VERSION_V2

    # 7. Re-save state in v2 format
    match state_module.save(ctx.ssm, ctx.s3, state):
        case Err() as e:
            return e
        case Ok(_):
            pass

    return Ok(
        MigrateResult(
            s3_migrated=s3_migrated,
            local_key_migrated=local_key_migrated,
            ca_stack_migrated=ca_stack_migrated,
            roles_updated=roles_updated,
        )
    )
