"""Kubernetes commands - manage K8s clusters and workloads for Roles Anywhere."""

import click

from iam_ra_cli.commands.common import (
    aws_options,
    echo_key_value,
    echo_section,
    handle_result,
    json_option,
    make_context,
    namespace_option,
    to_json,
)
from iam_ra_cli.workflows import k8s as k8s_workflow


@click.group()
def k8s() -> None:
    """Manage Kubernetes integration for IAM Roles Anywhere.

    \b
    Two-level model:
      1. Cluster setup   - once per K8s cluster (CA + Issuer)
      2. Workload onboard - per application (Certificate + Pod)

    \b
    Quick start:
      iam-ra k8s setup prod-cluster
      iam-ra k8s onboard my-app --role admin --cluster prod-cluster
    """
    pass


@k8s.command("setup")
@click.argument("cluster_name")
@namespace_option
@aws_options
@click.option(
    "--k8s-namespace",
    "-k",
    default="default",
    show_default=True,
    help="Kubernetes namespace for CA secret and Issuer",
)
def k8s_setup(
    cluster_name: str,
    namespace: str,
    region: str,
    profile: str | None,
    k8s_namespace: str,
) -> None:
    """Set up a Kubernetes cluster for IAM Roles Anywhere.

    Generates cluster-level manifests: CA Secret and cert-manager Issuer.
    Apply these once per cluster before onboarding workloads.

    CLUSTER_NAME is a logical identifier for this K8s cluster (e.g., "prod", "staging").

    \b
    Prerequisites:
      - cert-manager must be installed in the cluster
      - IAM-RA namespace must be initialized with self-signed CA mode

    \b
    Examples:
      iam-ra k8s setup prod
      iam-ra k8s setup staging --k8s-namespace iam-ra-system

    \b
    After running, apply the manifests:
      iam-ra k8s setup prod | kubectl apply -f -
    """
    ctx = make_context(region, profile)

    result = handle_result(
        k8s_workflow.setup(ctx, namespace, cluster_name, k8s_namespace),
        success_message=f"Cluster '{cluster_name}' set up successfully!",
    )

    click.echo("# Apply these manifests to your cluster:", err=True)
    click.echo("# kubectl apply -f <this-output>", err=True)
    click.echo(result.manifests.to_yaml())


@k8s.command("teardown")
@click.argument("cluster_name")
@namespace_option
@aws_options
@click.option(
    "--yes",
    "-y",
    is_flag=True,
    help="Skip confirmation prompt",
)
def k8s_teardown(
    cluster_name: str,
    namespace: str,
    region: str,
    profile: str | None,
    yes: bool,
) -> None:
    """Remove a Kubernetes cluster from IAM-RA state.

    This only removes the cluster record from IAM-RA state.
    It does NOT interact with your actual K8s cluster.

    You must manually delete the CA Secret and Issuer from K8s:
      kubectl delete issuer iam-ra
      kubectl delete secret iam-ra-ca

    CLUSTER_NAME is the cluster to remove.

    \b
    Examples:
      iam-ra k8s teardown prod
      iam-ra k8s teardown staging --yes
    """
    if not yes:
        click.confirm(
            f"Remove cluster '{cluster_name}' from IAM-RA state?",
            abort=True,
        )

    ctx = make_context(region, profile)

    handle_result(
        k8s_workflow.teardown(ctx, namespace, cluster_name),
        success_message=f"Cluster '{cluster_name}' removed from state.",
    )

    click.echo()
    click.echo("Remember to clean up the K8s resources:")
    click.echo("  kubectl delete issuer iam-ra")
    click.echo("  kubectl delete secret iam-ra-ca")


@k8s.command("onboard")
@click.argument("workload_name")
@click.option(
    "--role",
    "-R",
    "role_name",
    required=True,
    help="IAM-RA role for this workload (must exist)",
)
@click.option(
    "--cluster",
    "-c",
    "cluster_name",
    required=True,
    help="K8s cluster (must be set up first)",
)
@namespace_option
@aws_options
@click.option(
    "--k8s-namespace",
    "-k",
    default="default",
    show_default=True,
    help="Kubernetes namespace for the workload",
)
@click.option(
    "--duration-hours",
    default=24,
    show_default=True,
    help="Certificate validity in hours",
)
def k8s_onboard(
    workload_name: str,
    role_name: str,
    cluster_name: str,
    namespace: str,
    region: str,
    profile: str | None,
    k8s_namespace: str,
    duration_hours: int,
) -> None:
    """Onboard a Kubernetes workload to IAM Roles Anywhere.

    Generates workload-level manifests: Certificate, ConfigMap, and sample Pod.

    WORKLOAD_NAME is a logical identifier for this workload (e.g., "payment-service").

    \b
    Prerequisites:
      - Cluster must be set up first (iam-ra k8s setup)
      - Role must exist (iam-ra role create)

    \b
    Examples:
      iam-ra k8s onboard payment-service --role admin --cluster prod
      iam-ra k8s onboard api-gateway --role readonly --cluster staging -k gateway

    \b
    After running, apply the manifests:
      iam-ra k8s onboard my-app --role admin --cluster prod | kubectl apply -f -
    """
    ctx = make_context(region, profile)

    result = handle_result(
        k8s_workflow.onboard(
            ctx,
            namespace,
            workload_name,
            cluster_name,
            role_name,
            k8s_namespace,
            duration_hours,
        ),
        success_message=f"Workload '{workload_name}' onboarded successfully!",
    )

    echo_key_value("Cluster", result.workload.cluster_name, err=True)
    echo_key_value("Role", result.workload.role_name, err=True)
    echo_key_value("K8s Namespace", result.workload.namespace, err=True)
    click.echo("# Apply these manifests to your cluster:", err=True)
    click.echo("# kubectl apply -f <this-output>", err=True)
    click.echo(result.manifests.to_yaml())


@k8s.command("offboard")
@click.argument("workload_name")
@namespace_option
@aws_options
@click.option(
    "--yes",
    "-y",
    is_flag=True,
    help="Skip confirmation prompt",
)
def k8s_offboard(
    workload_name: str,
    namespace: str,
    region: str,
    profile: str | None,
    yes: bool,
) -> None:
    """Remove a Kubernetes workload from IAM-RA state.

    This only removes the workload record from IAM-RA state.
    It does NOT interact with your actual K8s cluster.

    You must manually delete the Certificate, ConfigMap, and Pod from K8s.

    WORKLOAD_NAME is the workload to remove.

    \b
    Examples:
      iam-ra k8s offboard payment-service
      iam-ra k8s offboard api-gateway --yes
    """
    if not yes:
        click.confirm(
            f"Remove workload '{workload_name}' from IAM-RA state?",
            abort=True,
        )

    ctx = make_context(region, profile)

    handle_result(
        k8s_workflow.offboard(ctx, namespace, workload_name),
        success_message=f"Workload '{workload_name}' removed from state.",
    )

    click.echo()
    click.echo(f"Remember to clean up the K8s resources for '{workload_name}':")
    click.echo(f"  kubectl delete certificate {workload_name}-cert")
    click.echo(f"  kubectl delete configmap {workload_name}-iam-ra-config")
    click.echo(f"  kubectl delete pod {workload_name}-sample")


@k8s.command("list")
@namespace_option
@aws_options
@click.option(
    "--cluster",
    "-c",
    "cluster_name",
    default=None,
    help="Filter by cluster name",
)
@json_option
def k8s_list(
    namespace: str,
    region: str,
    profile: str | None,
    cluster_name: str | None,
    as_json: bool,
) -> None:
    """List Kubernetes clusters and workloads.

    \b
    Examples:
      iam-ra k8s list
      iam-ra k8s list --cluster prod
      iam-ra k8s list --json
    """
    ctx = make_context(region, profile)

    result = handle_result(k8s_workflow.list_k8s(ctx, namespace, cluster_name))

    if as_json:
        click.echo(to_json({"clusters": result.clusters, "workloads": result.workloads}))
        return

    if not result.clusters and not result.workloads:
        click.echo(f"No K8s resources in namespace '{namespace}'")
        click.echo()
        click.echo("Set up a cluster with: iam-ra k8s setup <cluster-name>")
        return

    # Show clusters
    if result.clusters:
        echo_section("Clusters")
        for name, cluster in sorted(result.clusters.items()):
            # Count workloads in this cluster
            workload_count = sum(1 for w in result.workloads.values() if w.cluster_name == name)
            click.echo(f"  {name} ({workload_count} workloads)")
        click.echo()

    # Show workloads
    if result.workloads:
        echo_section("Workloads")
        for name, workload in sorted(result.workloads.items()):
            click.echo(f"  {name}")
            echo_key_value("Cluster", workload.cluster_name, indent=2)
            echo_key_value("Role", workload.role_name, indent=2)
            echo_key_value("K8s Namespace", workload.namespace, indent=2)
            click.echo()
