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
    render_json,
)
from iam_ra_cli.lib.sops import get_nix_repo_root
from iam_ra_cli.workflows import list_hosts, offboard, onboard
from iam_ra_cli.workflows.host import (
    AddRoleConfig,
    OnboardConfig,
    OnboardResult,
    RemoveRoleConfig,
    RotateCertConfig,
    add_role,
    remove_role,
    rotate_cert,
)

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

    v3: multiple role_profiles render as multiple `profiles.<name> = { ... }`
    entries sharing the same cert/trust anchor.
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
        "       profiles = {",
    ]
    for rp in result.role_profiles:
        lines.extend(
            [
                f"         {rp.role_name} = {{",
                f'           profileArn = "{rp.profile_arn}";',
                f'           roleArn    = "{rp.role_arn}";',
                "         };",
            ]
        )
    lines.extend(
        [
            "       };",
            "     };",
            "",
            "3. Deploy and verify:",
            "",
        ]
    )
    for rp in result.role_profiles:
        lines.append(f"     aws sts get-caller-identity --profile {rp.role_name}")
    return lines


def _render_human(result: OnboardResult) -> None:
    """Emit the human-readable onboard summary to stdout via click.echo.

    Layout:
      1. Basic identifiers (hostname/namespace/region/roles)
      2. ARNs the user needs for Nix config (Trust Anchor + per-role profiles)
      3. Secrets file info (absolute + relative + SOPS keys)
      4. Next steps: Nix snippet + verification command
      5. Internal details (Secrets Manager ARNs) - de-emphasized at the end
    """
    click.echo()
    echo_key_value("Hostname", result.host.hostname, indent=1)
    echo_key_value("Namespace", result.namespace, indent=1)
    echo_key_value("Region", result.region, indent=1)
    # Display the list of roles; singular "Role" label if just one, plural
    # otherwise, to keep the existing phrasing for the scenario-1 case.
    role_label = "Role" if len(result.host.role_names) == 1 else "Roles"
    echo_key_value(role_label, ", ".join(result.host.role_names), indent=1)

    click.echo()
    click.secho("Identifiers for Nix config:", bold=True)
    echo_key_value("Trust Anchor", str(result.trust_anchor_arn), indent=1)
    for rp in result.role_profiles:
        echo_key_value(f"Profile ({rp.role_name})", str(rp.profile_arn), indent=1)
        echo_key_value(f"Role ARN ({rp.role_name})", str(rp.role_arn), indent=1)

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


def _build_json_payload(result: OnboardResult) -> dict[str, object]:
    """Build the JSON payload for `host onboard --json`.

    Schema (v1 envelope, v3 content):
      {
        "hostname": str,
        "namespace": str,
        "region": str,
        "role_names": [str, ...],
        "trust_anchor_arn": str,
        "role_profiles": [
          { "role_name": str, "profile_arn": str, "role_arn": str },
          ...
        ],
        "secrets_file": {               # null when --no-sops
          "path": str,
          "relative_path": str | null,
          "encrypted": bool,
          "keys": [str, ...]
        } | null,
        "internal": {
          "stack_name": str,
          "certificate_secret_arn": str,
          "private_key_secret_arn": str
        }
      }
    """
    if result.secrets_file is not None:
        _abs, _root, rel = _sops_paths(result.secrets_file.path)
        secrets_file_payload: dict[str, object] | None = {
            "path": str(result.secrets_file.path.resolve()),
            "relative_path": str(rel) if rel is not None else None,
            "encrypted": result.secrets_file.encrypted,
            "keys": list(SOPS_KEYS),
        }
    else:
        secrets_file_payload = None

    return {
        "hostname": result.host.hostname,
        "namespace": result.namespace,
        "region": result.region,
        "role_names": list(result.host.role_names),
        "trust_anchor_arn": str(result.trust_anchor_arn),
        "role_profiles": [
            {
                "role_name": rp.role_name,
                "profile_arn": str(rp.profile_arn),
                "role_arn": str(rp.role_arn),
            }
            for rp in result.role_profiles
        ],
        "secrets_file": secrets_file_payload,
        "internal": {
            "stack_name": result.host.stack_name,
            "certificate_secret_arn": str(result.host.certificate_secret_arn),
            "private_key_secret_arn": str(result.host.private_key_secret_arn),
        },
    }


def _render_json(result: OnboardResult) -> None:
    """Emit the onboard result as JSON for scripts/automation."""
    click.echo(render_json(_build_json_payload(result)))


@click.group()
def host() -> None:
    """Manage hosts for Roles Anywhere."""
    pass


@host.command("onboard")
@click.argument("hostname")
@click.option(
    "--role",
    "-R",
    "role_flags",
    required=True,
    multiple=True,
    help=(
        "Role name to associate with this host. Pass multiple times or "
        "comma-separated to onboard with multiple roles under a single cert."
    ),
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
    role_flags: tuple[str, ...],
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

    A host can be onboarded with multiple roles as long as they all share
    the same scope (same trust anchor). Pass --role multiple times or use
    comma-separated values.

    \b
    Examples:
      iam-ra host onboard myhost --role admin
      iam-ra host onboard myhost --role readonly --validity-days 90
      iam-ra host onboard webserver --role app --no-sops
      iam-ra host onboard mbp --role admin --role readonly --role deploy
      iam-ra host onboard mbp --role admin,readonly,deploy
    """
    # Expand comma-separated values inside each --role flag + dedupe while
    # preserving order.
    role_names: list[str] = []
    for flag in role_flags:
        for name in flag.split(","):
            name = name.strip()
            if name and name not in role_names:
                role_names.append(name)

    if not as_json:
        click.echo(f"Onboarding host: {hostname}")
        echo_key_value("Namespace", namespace, indent=1)
        if len(role_names) == 1:
            echo_key_value("Role", role_names[0], indent=1)
        else:
            echo_key_value("Roles", ", ".join(role_names), indent=1)
        echo_key_value("Validity", f"{validity_days} days", indent=1)
        click.echo()

    ctx = make_context(region, profile)
    config = OnboardConfig(
        namespace=namespace,
        hostname=hostname,
        role_names=tuple(role_names),
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
        as_json=as_json,
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

    hosts = handle_result(list_hosts(ctx, namespace), as_json=as_json)

    if as_json:
        # Schema (v1 envelope, v3 content):
        #   { "schema_version": "v1",
        #     "namespace": str,
        #     "items": [
        #       { "hostname": str, "role_names": [str, ...], "scope": str,
        #         "internal": { "stack_name": str,
        #                       "certificate_secret_arn": str,
        #                       "private_key_secret_arn": str } },
        #       ...
        #     ]
        #   }
        items = [
            {
                "hostname": h.hostname,
                "role_names": list(h.role_names),
                "scope": h.scope,
                "internal": {
                    "stack_name": h.stack_name,
                    "certificate_secret_arn": str(h.certificate_secret_arn),
                    "private_key_secret_arn": str(h.private_key_secret_arn),
                },
            }
            for h in sorted(hosts.values(), key=lambda h: h.hostname)
        ]
        click.echo(render_json({"namespace": namespace, "items": items}))
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
        roles_label = "Role" if len(h.role_names) == 1 else "Roles"
        echo_key_value(roles_label, ", ".join(h.role_names), indent=2)
        echo_key_value("Scope", h.scope, indent=2)
        echo_key_value("Stack", h.stack_name, indent=2)
        click.echo()


@host.command("add-role")
@click.argument("hostname")
@click.argument("role_name")
@namespace_option
@aws_options
@click.option(
    "--sops-output",
    type=click.Path(),
    default=None,
    help=(
        "Override the SOPS file path. Defaults to "
        "secrets/hosts/<hostname>/iam-ra.yaml relative to the Nix flake root."
    ),
)
@json_option
def host_add_role(
    hostname: str,
    role_name: str,
    namespace: str,
    region: str,
    profile: str | None,
    sops_output: str | None,
    as_json: bool,
) -> None:
    """Attach another role to an existing host (no new cert issued).

    The role must live in the same scope as the host's existing cert (same
    trust anchor, same account). For cross-scope / cross-account hosts use
    the multi-identity workflow (scenario 3).

    \b
    Examples:
      iam-ra host add-role myhost readonly
      iam-ra host add-role myhost deploy --namespace prod
    """
    if not as_json:
        click.echo(f"Adding role to host: {hostname}")
        echo_key_value("Namespace", namespace, indent=1)
        echo_key_value("Role", role_name, indent=1)
        click.echo()

    ctx = make_context(region, profile)
    config = AddRoleConfig(
        namespace=namespace,
        hostname=hostname,
        role_name=role_name,
        sops_path=Path(sops_output) if sops_output else None,
    )

    result = handle_result(
        add_role(ctx, config),
        success_message=(
            None
            if as_json
            else f"Role '{role_name}' attached to host '{hostname}'."
        ),
        as_json=as_json,
    )

    if as_json:
        # Schema: { schema_version, hostname, role_name, already_present,
        #           sops_file_path, updated_role_names: [str, ...] }
        click.echo(
            render_json(
                {
                    "hostname": result.hostname,
                    "role_name": result.role_name,
                    "already_present": result.already_present,
                    "sops_file_path": str(result.sops_file_path),
                    "updated_role_names": list(result.updated_role_names),
                }
            )
        )
        return

    # Human output
    if result.already_present:
        click.echo(
            f"  Role '{result.role_name}' was already attached to this host. "
            f"No changes."
        )
    else:
        click.echo("  SOPS file updated with the new profile.")
    click.echo()
    echo_key_value("SOPS file", str(result.sops_file_path), indent=1)
    echo_key_value(
        "Roles now attached", ", ".join(result.updated_role_names), indent=1
    )


@host.command("remove-role")
@click.argument("hostname")
@click.argument("role_name")
@namespace_option
@aws_options
@click.option(
    "--sops-output",
    type=click.Path(),
    default=None,
    help=(
        "Override the SOPS file path. Defaults to "
        "secrets/hosts/<hostname>/iam-ra.yaml relative to the Nix flake root."
    ),
)
@json_option
def host_remove_role(
    hostname: str,
    role_name: str,
    namespace: str,
    region: str,
    profile: str | None,
    sops_output: str | None,
    as_json: bool,
) -> None:
    """Detach a role from a host (does NOT destroy the host).

    Fails if this would remove the host's last role - use
    'iam-ra host offboard' to remove the host entirely.

    \b
    Examples:
      iam-ra host remove-role myhost readonly
      iam-ra host remove-role myhost deploy --namespace prod
    """
    if not as_json:
        click.echo(f"Removing role from host: {hostname}")
        echo_key_value("Namespace", namespace, indent=1)
        echo_key_value("Role", role_name, indent=1)
        click.echo()

    ctx = make_context(region, profile)
    config = RemoveRoleConfig(
        namespace=namespace,
        hostname=hostname,
        role_name=role_name,
        sops_path=Path(sops_output) if sops_output else None,
    )

    result = handle_result(
        remove_role(ctx, config),
        success_message=(
            None
            if as_json
            else f"Role '{role_name}' detached from host '{hostname}'."
        ),
        as_json=as_json,
    )

    if as_json:
        # Schema: { schema_version, hostname, role_name, already_absent,
        #           sops_file_path, updated_role_names: [str, ...] }
        click.echo(
            render_json(
                {
                    "hostname": result.hostname,
                    "role_name": result.role_name,
                    "already_absent": result.already_absent,
                    "sops_file_path": str(result.sops_file_path),
                    "updated_role_names": list(result.updated_role_names),
                }
            )
        )
        return

    if result.already_absent:
        click.echo(
            f"  Role '{result.role_name}' wasn't attached to this host. "
            f"No changes."
        )
    else:
        click.echo("  SOPS file updated; profile removed.")
    click.echo()
    echo_key_value("SOPS file", str(result.sops_file_path), indent=1)
    echo_key_value(
        "Roles now attached",
        ", ".join(result.updated_role_names) or "(none)",
        indent=1,
    )


@host.command("rotate-cert")
@click.argument("hostname")
@namespace_option
@aws_options
@click.option(
    "--validity-days",
    default=365,
    show_default=True,
    help="Validity (days) for the new cert",
)
@click.option(
    "--sops-output",
    type=click.Path(),
    default=None,
    help=(
        "Override the SOPS file path. Defaults to "
        "secrets/hosts/<hostname>/iam-ra.yaml relative to the Nix flake root."
    ),
)
@json_option
def host_rotate_cert(
    hostname: str,
    namespace: str,
    region: str,
    profile: str | None,
    validity_days: int,
    sops_output: str | None,
    as_json: bool,
) -> None:
    """Issue a new cert for an existing host.

    The cert is signed by the same CA the host was originally onboarded
    under. Secrets Manager secrets are updated in place (new version,
    same ARN). The SOPS file is rewritten with the new cert and key
    while preserving all existing profile entries.

    Does NOT touch CloudFormation or role attachments. Use this to renew
    a cert that's about to expire without disturbing the host's roles.

    \b
    Examples:
      iam-ra host rotate-cert myhost
      iam-ra host rotate-cert myhost --validity-days 90
    """
    if not as_json:
        click.echo(f"Rotating cert for host: {hostname}")
        echo_key_value("Namespace", namespace, indent=1)
        echo_key_value("Validity", f"{validity_days} days", indent=1)
        click.echo()

    ctx = make_context(region, profile)
    config = RotateCertConfig(
        namespace=namespace,
        hostname=hostname,
        validity_days=validity_days,
        sops_path=Path(sops_output) if sops_output else None,
    )

    result = handle_result(
        rotate_cert(ctx, config),
        success_message=(
            None if as_json else f"Cert rotated for host '{hostname}'."
        ),
        as_json=as_json,
    )

    if as_json:
        # Schema: { schema_version, hostname, scope, sops_file_path,
        #           role_names: [str, ...] }
        click.echo(
            render_json(
                {
                    "hostname": result.hostname,
                    "scope": result.scope,
                    "sops_file_path": str(result.sops_file_path),
                    "role_names": list(result.role_names),
                }
            )
        )
        return

    click.echo(
        "  New cert issued, Secrets Manager updated, SOPS file rewritten."
    )
    click.echo()
    echo_key_value("SOPS file", str(result.sops_file_path), indent=1)
    echo_key_value("Scope", result.scope, indent=1)
    echo_key_value(
        "Roles unchanged", ", ".join(result.role_names), indent=1
    )
