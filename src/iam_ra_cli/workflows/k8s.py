"""Kubernetes workflows - setup, teardown, onboard, offboard, list.

Workflows for managing K8s cluster and workload configurations
that use IAM Roles Anywhere for AWS credentials.
"""

from dataclasses import dataclass

from iam_ra_cli.lib import state as state_module
from iam_ra_cli.lib.aws import AwsContext
from iam_ra_cli.lib.errors import (
    CAKeyNotFoundError,
    CAScopeNotFoundError,
    K8sClusterInUseError,
    K8sClusterNotFoundError,
    K8sWorkloadNotFoundError,
    NotInitializedError,
    RoleNotFoundError,
    S3ReadError,
    StateLoadError,
    StateSaveError,
)
from iam_ra_cli.lib.k8s import (
    WorkloadManifests,
    generate_workload_manifests,
)
from iam_ra_cli.lib.result import Err, Ok, Result
from iam_ra_cli.lib.storage.s3 import read_object
from iam_ra_cli.models import CAMode, K8sCluster, K8sWorkload
from iam_ra_cli.operations.ca import _ca_cert_s3_key, _ca_key_local_path

# =============================================================================
# Error Type Aliases
# =============================================================================

type SetupError = NotInitializedError | StateLoadError | StateSaveError

type TeardownError = (
    NotInitializedError
    | K8sClusterNotFoundError
    | K8sClusterInUseError
    | StateLoadError
    | StateSaveError
)

type OnboardError = (
    NotInitializedError
    | K8sClusterNotFoundError
    | RoleNotFoundError
    | CAScopeNotFoundError
    | CAKeyNotFoundError
    | S3ReadError
    | StateLoadError
    | StateSaveError
)

type OffboardError = (
    NotInitializedError | K8sWorkloadNotFoundError | StateLoadError | StateSaveError
)

type ListError = NotInitializedError | StateLoadError


# =============================================================================
# Result Types
# =============================================================================


@dataclass(frozen=True)
class SetupResult:
    """Result of cluster setup."""

    cluster: K8sCluster


@dataclass(frozen=True)
class OnboardResult:
    """Result of workload onboarding."""

    workload: K8sWorkload
    manifests: WorkloadManifests


@dataclass(frozen=True)
class ListResult:
    """Result of listing K8s resources."""

    clusters: dict[str, K8sCluster]
    workloads: dict[str, K8sWorkload]


# =============================================================================
# Workflows
# =============================================================================


def setup(
    ctx: AwsContext,
    namespace: str,
    cluster_name: str,
) -> Result[SetupResult, SetupError]:
    """Register a K8s cluster for IAM Roles Anywhere.

    Just registers the cluster in state. CA manifests are generated
    per-namespace during onboard using the role's scope CA.

    Idempotent: if the cluster already exists, returns it without
    modifying state.

    Args:
        ctx: AWS context
        namespace: IAM-RA namespace
        cluster_name: Logical name for the K8s cluster

    Returns:
        SetupResult with cluster info
    """
    # Load state
    match state_module.load(ctx.ssm, ctx.s3, namespace):
        case Err(e):
            return Err(e)
        case Ok(None):
            return Err(NotInitializedError(namespace))
        case Ok(state):
            pass

    if not state.is_initialized:
        return Err(NotInitializedError(namespace))

    # Create or retrieve cluster record (idempotent)
    already_exists = cluster_name in state.k8s_clusters
    cluster = state.k8s_clusters.get(cluster_name, K8sCluster(name=cluster_name))

    if not already_exists:
        state.k8s_clusters[cluster_name] = cluster
        match state_module.save(ctx.ssm, ctx.s3, state):
            case Err() as e:
                return e
            case Ok(_):
                pass

    return Ok(SetupResult(cluster=cluster))


def teardown(
    ctx: AwsContext,
    namespace: str,
    cluster_name: str,
) -> Result[None, TeardownError]:
    """Remove a K8s cluster from state.

    Does not interact with the actual K8s cluster - just removes
    the record from IAM-RA state.

    Args:
        ctx: AWS context
        namespace: IAM-RA namespace
        cluster_name: Cluster to remove

    Returns:
        None on success
    """
    # Load state
    match state_module.load(ctx.ssm, ctx.s3, namespace):
        case Err(e):
            return Err(e)
        case Ok(None):
            return Err(NotInitializedError(namespace))
        case Ok(state):
            pass

    if not state.is_initialized:
        return Err(NotInitializedError(namespace))

    # Check cluster exists
    if cluster_name not in state.k8s_clusters:
        return Err(K8sClusterNotFoundError(cluster_name))

    # Check no workloads reference this cluster
    workloads_using = [
        w.name for w in state.k8s_workloads.values() if w.cluster_name == cluster_name
    ]
    if workloads_using:
        return Err(K8sClusterInUseError(cluster_name, tuple(workloads_using)))

    # Remove from state
    del state.k8s_clusters[cluster_name]
    match state_module.save(ctx.ssm, ctx.s3, state):
        case Err() as e:
            return e
        case Ok(_):
            pass

    return Ok(None)


def onboard(
    ctx: AwsContext,
    namespace: str,
    workload_name: str,
    cluster_name: str,
    role_name: str,
    k8s_namespace: str = "default",
    duration_hours: int = 24,
    include_sample_pod: bool = True,
) -> Result[OnboardResult, OnboardError]:
    """Onboard a K8s workload to IAM Roles Anywhere.

    Generates all manifests for the workload's namespace:
    - CA Secret + Issuer (using the role's scope CA)
    - Certificate (signed by the scope's Issuer)
    - ConfigMap (with scope's Trust Anchor ARN)
    - Optional sample Pod

    The scope is derived from the role: each role belongs to a scope,
    and its scope's CA provides cryptographic isolation per namespace.

    Idempotent: if the workload already exists, regenerates and returns
    the manifests without modifying state.

    Args:
        ctx: AWS context
        namespace: IAM-RA namespace
        workload_name: Logical name for the workload
        cluster_name: K8s cluster (must be set up first)
        role_name: IAM-RA role for the workload to assume
        k8s_namespace: K8s namespace for the workload
        duration_hours: Certificate validity in hours
        include_sample_pod: Whether to include the sample Pod manifest

    Returns:
        OnboardResult with workload info and manifests
    """
    # Load state
    match state_module.load(ctx.ssm, ctx.s3, namespace):
        case Err(e):
            return Err(e)
        case Ok(None):
            return Err(NotInitializedError(namespace))
        case Ok(state):
            pass

    if not state.is_initialized:
        return Err(NotInitializedError(namespace))

    assert state.init is not None

    # Check cluster exists
    if cluster_name not in state.k8s_clusters:
        return Err(K8sClusterNotFoundError(cluster_name))

    # Check role exists
    if role_name not in state.roles:
        return Err(RoleNotFoundError(namespace, role_name))

    role = state.roles[role_name]
    scope = role.scope

    # Validate scope has a CA set up
    if scope not in state.cas:
        return Err(CAScopeNotFoundError(namespace, scope))

    scope_ca = state.cas[scope]

    # Only self-signed CA is supported for K8s
    if scope_ca.mode != CAMode.SELF_SIGNED:
        return Err(CAScopeNotFoundError(namespace, scope))

    # Load scope's CA certificate from S3
    bucket_name = state.init.bucket_arn.resource_id
    ca_cert_key = _ca_cert_s3_key(namespace, scope)

    match read_object(ctx.s3, bucket_name, ca_cert_key):
        case Err(e):
            return Err(e)
        case Ok(ca_cert_pem):
            pass

    # Load scope's CA private key from local storage
    ca_key_path = _ca_key_local_path(namespace, scope)
    if not ca_key_path.exists():
        return Err(CAKeyNotFoundError(ca_key_path))
    ca_key_pem = ca_key_path.read_text()

    # Generate manifests with scope's CA material and trust anchor
    manifests = generate_workload_manifests(
        workload_name=workload_name,
        trust_anchor_arn=str(scope_ca.trust_anchor_arn),
        profile_arn=str(role.profile_arn),
        role_arn=str(role.role_arn),
        namespace=k8s_namespace,
        duration_hours=duration_hours,
        include_sample_pod=include_sample_pod,
        # Always include CA Secret + Issuer for the namespace
        cluster_namespace="__always_include__",
        ca_cert_pem=ca_cert_pem,
        ca_key_pem=ca_key_pem,
    )

    # Create or retrieve workload record (idempotent)
    already_exists = workload_name in state.k8s_workloads
    workload = state.k8s_workloads.get(
        workload_name,
        K8sWorkload(
            name=workload_name,
            cluster_name=cluster_name,
            role_name=role_name,
            namespace=k8s_namespace,
        ),
    )

    if not already_exists:
        state.k8s_workloads[workload_name] = workload
        match state_module.save(ctx.ssm, ctx.s3, state):
            case Err() as e:
                return e
            case Ok(_):
                pass

    return Ok(OnboardResult(workload=workload, manifests=manifests))


def offboard(
    ctx: AwsContext,
    namespace: str,
    workload_name: str,
) -> Result[None, OffboardError]:
    """Remove a K8s workload from state.

    Does not interact with the actual K8s cluster - just removes
    the record from IAM-RA state.

    Args:
        ctx: AWS context
        namespace: IAM-RA namespace
        workload_name: Workload to remove

    Returns:
        None on success
    """
    # Load state
    match state_module.load(ctx.ssm, ctx.s3, namespace):
        case Err(e):
            return Err(e)
        case Ok(None):
            return Err(NotInitializedError(namespace))
        case Ok(state):
            pass

    if not state.is_initialized:
        return Err(NotInitializedError(namespace))

    # Check workload exists
    if workload_name not in state.k8s_workloads:
        return Err(K8sWorkloadNotFoundError(workload_name))

    # Remove from state
    del state.k8s_workloads[workload_name]
    match state_module.save(ctx.ssm, ctx.s3, state):
        case Err() as e:
            return e
        case Ok(_):
            pass

    return Ok(None)


def list_k8s(
    ctx: AwsContext,
    namespace: str,
    cluster_name: str | None = None,
) -> Result[ListResult, ListError]:
    """List K8s clusters and workloads.

    Args:
        ctx: AWS context
        namespace: IAM-RA namespace
        cluster_name: Optional filter by cluster

    Returns:
        ListResult with clusters and workloads
    """
    # Load state
    match state_module.load(ctx.ssm, ctx.s3, namespace):
        case Err(e):
            return Err(e)
        case Ok(None):
            return Err(NotInitializedError(namespace))
        case Ok(state):
            pass

    if not state.is_initialized:
        return Err(NotInitializedError(namespace))

    clusters = state.k8s_clusters
    workloads = state.k8s_workloads

    # Filter by cluster if specified
    if cluster_name is not None:
        clusters = {k: v for k, v in clusters.items() if k == cluster_name}
        workloads = {k: v for k, v in workloads.items() if v.cluster_name == cluster_name}

    return Ok(ListResult(clusters=clusters, workloads=workloads))
