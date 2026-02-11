"""Kubernetes workflows - setup, teardown, onboard, offboard, list.

Workflows for managing K8s cluster and workload configurations
that use IAM Roles Anywhere for AWS credentials.
"""

from dataclasses import dataclass

from iam_ra_cli.lib import state as state_module
from iam_ra_cli.lib.aws import AwsContext
from iam_ra_cli.lib.errors import (
    K8sClusterAlreadyExistsError,
    K8sClusterInUseError,
    K8sClusterNotFoundError,
    K8sUnsupportedCAModeError,
    K8sWorkloadAlreadyExistsError,
    K8sWorkloadNotFoundError,
    NotInitializedError,
    RoleNotFoundError,
    S3ReadError,
    StateLoadError,
    StateSaveError,
)
from iam_ra_cli.lib.k8s import (
    ClusterManifests,
    WorkloadManifests,
    generate_cluster_manifests,
    generate_workload_manifests,
)
from iam_ra_cli.lib.result import Err, Ok, Result
from iam_ra_cli.lib.storage.s3 import read_object
from iam_ra_cli.models import CAMode, K8sCluster, K8sWorkload

# =============================================================================
# Error Type Aliases
# =============================================================================

type SetupError = (
    NotInitializedError
    | K8sClusterAlreadyExistsError
    | K8sUnsupportedCAModeError
    | S3ReadError
    | StateLoadError
    | StateSaveError
)

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
    | K8sWorkloadAlreadyExistsError
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
    manifests: ClusterManifests


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


def _ca_cert_s3_key(namespace: str) -> str:
    """S3 key for CA certificate."""
    return f"{namespace}/ca/certificate.pem"


def setup(
    ctx: AwsContext,
    namespace: str,
    cluster_name: str,
    k8s_namespace: str = "default",
) -> Result[SetupResult, SetupError]:
    """Set up a K8s cluster for IAM Roles Anywhere.

    Creates cluster-level manifests (CA Secret + Issuer) for cert-manager.
    Only supported for self-signed CA mode.

    Args:
        ctx: AWS context
        namespace: IAM-RA namespace
        cluster_name: Logical name for the K8s cluster
        k8s_namespace: K8s namespace for CA secret and issuer

    Returns:
        SetupResult with cluster info and manifests
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
    assert state.ca is not None

    # Check cluster doesn't already exist
    if cluster_name in state.k8s_clusters:
        return Err(K8sClusterAlreadyExistsError(cluster_name))

    # Only self-signed CA is supported for K8s
    if state.ca.mode != CAMode.SELF_SIGNED:
        return Err(K8sUnsupportedCAModeError(state.ca.mode.value))

    # Load CA certificate from S3
    bucket_name = state.init.bucket_arn.resource_id
    ca_cert_key = _ca_cert_s3_key(namespace)

    match read_object(ctx.s3, bucket_name, ca_cert_key):
        case Err(e):
            return Err(e)
        case Ok(ca_cert_pem):
            pass

    # Generate manifests
    manifests = generate_cluster_manifests(
        ca_cert_pem=ca_cert_pem,
        namespace=k8s_namespace,
    )

    # Create cluster record
    cluster = K8sCluster(name=cluster_name)

    # Update state
    state.k8s_clusters[cluster_name] = cluster
    match state_module.save(ctx.ssm, ctx.s3, state):
        case Err() as e:
            return e
        case Ok(_):
            pass

    return Ok(SetupResult(cluster=cluster, manifests=manifests))


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
) -> Result[OnboardResult, OnboardError]:
    """Onboard a K8s workload to IAM Roles Anywhere.

    Generates workload-level manifests (Certificate + ConfigMap + sample Pod).

    Args:
        ctx: AWS context
        namespace: IAM-RA namespace
        workload_name: Logical name for the workload
        cluster_name: K8s cluster (must be set up first)
        role_name: IAM-RA role for the workload to assume
        k8s_namespace: K8s namespace for the workload
        duration_hours: Certificate validity in hours

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

    assert state.ca is not None

    # Check cluster exists
    if cluster_name not in state.k8s_clusters:
        return Err(K8sClusterNotFoundError(cluster_name))

    # Check role exists
    if role_name not in state.roles:
        return Err(RoleNotFoundError(namespace, role_name))

    # Check workload doesn't already exist
    if workload_name in state.k8s_workloads:
        return Err(K8sWorkloadAlreadyExistsError(workload_name))

    role = state.roles[role_name]

    # Generate manifests
    manifests = generate_workload_manifests(
        workload_name=workload_name,
        trust_anchor_arn=str(state.ca.trust_anchor_arn),
        profile_arn=str(role.profile_arn),
        role_arn=str(role.role_arn),
        namespace=k8s_namespace,
        duration_hours=duration_hours,
    )

    # Create workload record
    workload = K8sWorkload(
        name=workload_name,
        cluster_name=cluster_name,
        role_name=role_name,
        namespace=k8s_namespace,
    )

    # Update state
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
