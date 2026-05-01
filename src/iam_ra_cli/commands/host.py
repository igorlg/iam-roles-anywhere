"""Host commands - manage hosts for Roles Anywhere."""

from pathlib import Path

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
from iam_ra_cli.lib.sops import get_nix_repo_root
from iam_ra_cli.workflows import list_hosts, offboard, onboard
from iam_ra_cli.workflows.host import OnboardConfig, OnboardResult

# Keys written into the SOPS file by operations/secrets.py::create_secrets_file.
# Kept in sync with lib/sops.py::create_secrets_yaml.
SOPS_KEYS = (
    "certificate",
    "private_key",
    "trust_anchor_arn",
    "profile_arn",
    "role_arn",
    "region",
)


def _sops_paths(sops_path: Path) -> tuple[Path, Path | None, Path | None]:
    """Return (absolute_path, repo_root, relative_path_from_repo_root_or_None).

    When the SOPS file lives inside a Nix flake (detected via a walk-up
    to flake.nix), the relative path is useful for pasting into Nix
    expressions. When it lives outside (e.g. a --sops-output in /tmp),
    the relative form is None.
    """
    absolute = sops_path.resolve()
    repo_root = get_nix_repo_root()
    if repo_root is None:
        return absolute, None, None
    try:
        rel = absolute.relative_to(repo_root.resolve())
    except ValueError:
        return absolute, repo_root, None
    return absolute, repo_root, rel


def _render_nix_snippet(result: OnboardResult, rel_sops_path: Path | None) -> list[str]:
    """Build a Nix snippet that uses the documented programs.iamRolesAnywhere
    module API. Users with custom factory/wrapper patterns adapt as needed.

    If rel_sops_path is None (SOPS file outside a flake repo), the snippet
    uses a placeholder that the user must edit; otherwise the real Nix
    path literal (e.g. ./secrets/hosts/myhost/iam-ra.yaml) is used.
    """
    sops_nix_path = f"./{rel_sops_path}" if rel_sops_path else "./path/to/iam-ra.yaml"
    lines = [
        "1. Reference the SOPS keys in your Nix config:",
        "",
        '     sops.secrets."iam-ra/cert" = {',
        f"       sopsFile = {sops_nix_path};",
        '       key = "certificate";',
        "     };",
        '     sops.secrets."iam-ra/key" = {',
        f"       sopsFile = {sops_nix_path};",
        '       key = "private_key";',
        "     };",
        "",
        "2. Enable IAM Roles Anywhere for this host:",
        "",
        "     programs.iamRolesAnywhere = {",
        "       enable = true;",
        "       certificate = {",
        '         certPath = config.sops.secrets."iam-ra/cert".path;',
        '         keyPath  = config.sops.secrets."iam-ra/key".path;',
        "       };",
        f'       trustAnchorArn = "{result.trust_anchor_arn}";',
        f'       region = "{result.region}";',
        f"       profiles.{result.host.role_name} = {{",
        f'         profileArn = "{result.profile_arn}";',
        f'         roleArn    = "{result.role_arn}";',
        "       };",
        "     };",
        "",
        "3. Deploy and verify:",
        "",
        f"     aws sts get-caller-identity --profile {result.host.role_name}",
    ]
    return lines


def _render_human(result: OnboardResult) -> None:
    """Emit the human-readable onboard summary to stdout via click.echo.

    Layout:
      1. Basic identifiers (hostname/namespace/region/role)
      2. ARNs the user needs for Nix config (Trust Anchor, Profile, Role)
      3. Secrets file info (absolute + relative + SOPS keys)
      4. Next steps: Nix snippet + verification command
      5. Internal details (Secrets Manager ARNs) - de-emphasized at the end
    """
    click.echo()
    echo_key_value("Hostname", result.host.hostname, indent=1)
    echo_key_value("Namespace", result.namespace, indent=1)
    echo_key_value("Region", result.region, indent=1)
    echo_key_value("Role", result.host.role_name, indent=1)

    click.echo()
    click.secho("Identifiers for Nix config:", bold=True)
    echo_key_value("Trust Anchor", str(result.trust_anchor_arn), indent=1)
    echo_key_value("Profile", str(result.profile_arn), indent=1)
    echo_key_value("Role ARN", str(result.role_arn), indent=1)

    if result.secrets_file:
        absolute, _repo_root, relative = _sops_paths(result.secrets_file.path)
        click.echo()
        click.secho("Secrets file:", bold=True)
        echo_key_value("Path", str(absolute), indent=1)
        if relative is not None:
            echo_key_value("Relative", f"./{relative} (from flake root)", indent=1)
        echo_key_value("SOPS keys", ", ".join(SOPS_KEYS), indent=1)

        click.echo()
        click.secho("Next steps:", bold=True)
        click.echo()
        for line in _render_nix_snippet(result, relative):
            click.echo(f"  {line}")
    else:
        # --no-sops case: user manages secrets themselves, just show ARNs.
        click.echo()
        click.secho("Next steps:", bold=True)
        click.echo()
        click.echo(
            "  Fetch the certificate and private key from Secrets Manager, then"
        )
        click.echo("  configure programs.iamRolesAnywhere in your Nix host with the")
        click.echo("  identifiers above.")

    # De-emphasized: Secrets Manager ARNs (internal AWS resources - users rarely
    # reference these directly in Nix, but keep them for debugging/automation).
    click.echo()
    click.secho("Internal:", dim=True)
    echo_key_value(
        "Certificate secret", str(result.host.certificate_secret_arn), indent=1
    )
    echo_key_value(
        "Private key secret", str(result.host.private_key_secret_arn), indent=1
    )


def _render_json(result: OnboardResult) -> None:
    """Emit the onboard result as JSON for scripts/automation.

    TODO: implement proper JSON shape. Candidate schema:
        {
          "hostname": "...",
          "namespace": "...",
          "region": "...",
          "role_name": "...",
          "trust_anchor_arn": "...",
          "profile_arn": "...",
          "role_arn": "...",
          "secrets_file": {
            "path": "/abs/path/iam-ra.yaml",
            "relative_path": "secrets/hosts/.../iam-ra.yaml",  // null if outside repo
            "keys": ["certificate", "private_key", ...],
            "encrypted": true
          },
          "internal": {
            "certificate_secret_arn": "...",
            "private_key_secret_arn": "...",
            "stack_name": "..."
          }
        }
    Until implemented, fall back to the generic to_json() serializer.
    """
    # TODO(#TBD): replace with the schema above; exposing the dataclass as-is
    # leaks internal field names but is better than nothing for scripts.
    click.echo(to_json(result))


@click.group()
def host() -> None:
    """Manage hosts for Roles Anywhere."""
    pass


@host.command("onboard")
@click.argument("hostname")
@click.option(
    "--role",
    "-R",
    "role_name",
    required=True,
    help="Role name to associate with this host (must exist)",
)
@namespace_option
@aws_options
@click.option(
    "--validity-days",
    default=365,
    show_default=True,
    help="Certificate validity in days",
)
@click.option(
    "--no-sops",
    is_flag=True,
    help="Skip creating SOPS-encrypted secrets file",
)
@click.option(
    "--sops-output",
    type=click.Path(),
    default=None,
    help="Custom output path for SOPS file",
)
@click.option(
    "--overwrite",
    is_flag=True,
    help="Overwrite existing host/secrets",
)
@json_option
def host_onboard(
    hostname: str,
    role_name: str,
    namespace: str,
    region: str,
    profile: str | None,
    validity_days: int,
    no_sops: bool,
    sops_output: str | None,
    overwrite: bool,
    as_json: bool,
) -> None:
    """Onboard a host to IAM Roles Anywhere.

    Generates a host certificate, stores it in Secrets Manager, and
    optionally creates a SOPS-encrypted secrets file for Nix deployment.

    HOSTNAME is the identifier for this host (used in certificate CN).

    \b
    Examples:
      iam-ra host onboard myhost --role admin
      iam-ra host onboard myhost --role readonly --validity-days 90
      iam-ra host onboard webserver --role app --no-sops
    """
    if not as_json:
        click.echo(f"Onboarding host: {hostname}")
        echo_key_value("Namespace", namespace, indent=1)
        echo_key_value("Role", role_name, indent=1)
        echo_key_value("Validity", f"{validity_days} days", indent=1)
        click.echo()

    ctx = make_context(region, profile)
    config = OnboardConfig(
        namespace=namespace,
        hostname=hostname,
        role_name=role_name,
        validity_days=validity_days,
        create_sops=not no_sops,
        sops_output_path=Path(sops_output) if sops_output else None,
        overwrite=overwrite,
    )

    if not as_json:
        click.echo("[1/3] Generating host certificate...")
        click.echo("[2/3] Deploying host stack...")
        if not no_sops:
            click.echo("[3/3] Creating SOPS secrets file...")

    result = handle_result(
        onboard(ctx, config),
        success_message=(
            None if as_json else f"Host '{hostname}' onboarded successfully!"
        ),
    )

    if as_json:
        _render_json(result)
    else:
        _render_human(result)


@host.command("offboard")
@click.argument("hostname")
@namespace_option
@aws_options
def host_offboard(
    hostname: str,
    namespace: str,
    region: str,
    profile: str | None,
) -> None:
    """Offboard a host from IAM Roles Anywhere.

    Deletes the host stack and cleans up S3 artifacts.
    Does NOT delete local SOPS files.

    HOSTNAME is the identifier of the host to offboard.

    \b
    Examples:
      iam-ra host offboard myhost
      iam-ra host offboard webserver --namespace prod
    """
    click.echo(f"Offboarding host: {hostname}")

    ctx = make_context(region, profile)

    handle_result(
        offboard(ctx, namespace, hostname),
        success_message=f"Host '{hostname}' offboarded successfully!",
    )


@host.command("list")
@namespace_option
@aws_options
@json_option
def host_list(
    namespace: str,
    region: str,
    profile: str | None,
    as_json: bool,
) -> None:
    """List all hosts in the namespace.

    \b
    Examples:
      iam-ra host list
      iam-ra host list --namespace prod
      iam-ra host list --json
    """
    ctx = make_context(region, profile)

    hosts = handle_result(list_hosts(ctx, namespace))

    if as_json:
        click.echo(to_json(hosts))
        return

    if not hosts:
        click.echo(f"No hosts in namespace '{namespace}'")
        click.echo()
        click.echo("Onboard one with: iam-ra host onboard <hostname> --role <name>")
        return

    click.echo(f"Hosts in namespace '{namespace}':")
    click.echo()
    for hostname, h in sorted(hosts.items()):
        click.echo(f"  {hostname}")
        echo_key_value("Role", h.role_name, indent=2)
        echo_key_value("Stack", h.stack_name, indent=2)
        click.echo()
