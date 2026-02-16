"""CA commands - manage Certificate Authorities by scope."""

import click

from iam_ra_cli.commands.common import (
    aws_options,
    echo_key_value,
    handle_result,
    json_option,
    make_context,
    namespace_option,
    to_json,
)
from iam_ra_cli.workflows.ca import (
    delete_scope as delete_scope_workflow,
    list_cas as list_cas_workflow,
    setup_ca as setup_ca_workflow,
)


@click.group()
def ca() -> None:
    """Manage Certificate Authorities (per-scope CAs)."""
    pass


@ca.command("setup")
@namespace_option
@aws_options
@click.option(
    "--scope",
    "-s",
    default="default",
    show_default=True,
    help="Scope name for this CA (e.g., cert-manager, longhorn-system)",
)
@click.option(
    "--ca-validity-years",
    default=10,
    show_default=True,
    help="CA certificate validity in years",
)
def ca_setup(
    namespace: str,
    region: str,
    profile: str | None,
    scope: str,
    ca_validity_years: int,
) -> None:
    """Set up a new CA for a scope.

    Creates a self-signed CA certificate and IAM Roles Anywhere Trust Anchor.
    Each scope gets cryptographic isolation: certs from one scope cannot
    assume roles belonging to another scope.

    \b
    Examples:
      iam-ra ca setup                                # default scope
      iam-ra ca setup --scope cert-manager           # per-namespace CA
      iam-ra ca setup --scope longhorn-system
    """
    if scope != "default":
        click.echo(f"Using scope: {scope}", err=True)

    click.echo(f"Setting up CA for scope '{scope}'")
    echo_key_value("Namespace", namespace, indent=1)
    echo_key_value("Scope", scope, indent=1)
    echo_key_value("Validity", f"{ca_validity_years} years", indent=1)
    click.echo()

    ctx = make_context(region, profile)

    new_ca = handle_result(
        setup_ca_workflow(ctx, namespace, scope=scope, validity_years=ca_validity_years),
        success_message=f"CA for scope '{scope}' ready!",
    )

    click.echo()
    echo_key_value("Stack", new_ca.stack_name, indent=1)
    echo_key_value("Trust Anchor", str(new_ca.trust_anchor_arn), indent=1)
    echo_key_value("Mode", new_ca.mode.value, indent=1)


@ca.command("delete")
@namespace_option
@aws_options
@click.option(
    "--scope",
    "-s",
    required=True,
    help="Scope name to delete",
)
@click.option(
    "--yes",
    is_flag=True,
    help="Skip confirmation prompt",
)
def ca_delete(
    namespace: str,
    region: str,
    profile: str | None,
    scope: str,
    yes: bool,
) -> None:
    """Delete a CA scope.

    Removes the CloudFormation stack (Trust Anchor) and the scope
    entry from state. Does NOT delete the S3 cert or local private key.

    \b
    Examples:
      iam-ra ca delete --scope cert-manager
      iam-ra ca delete --scope longhorn-system --yes
    """
    if not yes:
        click.confirm(
            f"Delete CA scope '{scope}' in namespace '{namespace}'?",
            abort=True,
        )

    click.echo(f"Deleting CA scope: {scope}")

    ctx = make_context(region, profile)

    handle_result(
        delete_scope_workflow(ctx, namespace, scope),
        success_message=f"CA scope '{scope}' deleted!",
    )


@ca.command("list")
@namespace_option
@aws_options
@json_option
def ca_list(
    namespace: str,
    region: str,
    profile: str | None,
    as_json: bool,
) -> None:
    """List all CA scopes.

    \b
    Examples:
      iam-ra ca list
      iam-ra ca list --namespace prod
      iam-ra ca list --json
    """
    ctx = make_context(region, profile)

    cas = handle_result(list_cas_workflow(ctx, namespace))

    if as_json:
        click.echo(to_json(cas))
        return

    if not cas:
        click.echo(f"No CA scopes in namespace '{namespace}'")
        click.echo()
        click.echo("Create one with: iam-ra ca setup --scope <name>")
        return

    click.echo(f"CA scopes in namespace '{namespace}':")
    click.echo()
    for scope_name, ca_info in sorted(cas.items()):
        click.echo(f"  [{scope_name}]")
        echo_key_value("Stack", ca_info.stack_name, indent=2)
        echo_key_value("Mode", ca_info.mode.value, indent=2)
        echo_key_value("Trust Anchor", str(ca_info.trust_anchor_arn), indent=2)
        if ca_info.pca_arn:
            echo_key_value("PCA ARN", str(ca_info.pca_arn), indent=2)
        click.echo()
