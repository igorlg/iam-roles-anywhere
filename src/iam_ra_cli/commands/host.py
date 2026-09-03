"""Host commands - manage hosts for Roles Anywhere."""

import sys
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
from iam_ra_cli.lib.keystore import (
    CredentialSource,
    FileCredentialSource,
    KeychainCredentialSource,
)
from iam_ra_cli.workflows import list_hosts, offboard
from iam_ra_cli.workflows.enrol import (
    ApproveConfig,
    EnrolConfig,
    RequestConfig,
    approve_certificate,
    enrol_host,
    request_certificate,
)
from iam_ra_cli.workflows.host import (
    AddRoleConfig,
    RemoveRoleConfig,
    RoleProfile,
    add_role,
    remove_role,
)


def _render_enrol_nix_snippet(
    *,
    hostname: str,
    scope: str,
    region: str,
    trust_anchor_arn: str,
    role_profiles: tuple[RoleProfile, ...],
    credential_source: CredentialSource | None,
) -> list[str]:
    """Build a Nix snippet for the v3 module API.

    Emits the `identities.<scope>` shape with an explicit `certificate.source`.
    No SOPS wiring: under v3 the private key is generated on the host and never
    travels, and the certificate is public, so neither needs a secrets manager.
    """
    lines = [
        "programs.iamRolesAnywhere = {",
        "  enable = true;",
        f"  identities.{scope} = {{",
        "    certificate = {",
    ]

    match credential_source:
        case FileCredentialSource(certificate_path, private_key_path):
            lines.extend(
                [
                    '      source   = "files";',
                    f'      certPath = "{certificate_path}";',
                    f'      keyPath  = "{private_key_path}";',
                ]
            )
        case KeychainCredentialSource(subject_common_name, _keychain_path):
            lines.extend(
                [
                    '      source = "macosKeychain";',
                    f'      selector.subject = "CN={subject_common_name}";',
                ]
            )
        case None:
            # Split flow: the certificate has not been installed on this
            # machine, so we cannot know the final paths.
            lines.extend(
                [
                    '      source   = "files";',
                    '      certPath = "/path/to/cert.pem";  # from `iam-ra host request`',
                    '      keyPath  = "/path/to/key.pem";',
                ]
            )

    lines.extend(
        [
            "    };",
            f'    trustAnchorArn = "{trust_anchor_arn}";',
            f'    region = "{region}";',
            "    profiles = {",
        ]
    )
    for rp in role_profiles:
        lines.extend(
            [
                f"      {rp.role_name} = {{",
                f'        profileArn = "{rp.profile_arn}";',
                f'        roleArn    = "{rp.role_arn}";',
                "      };",
            ]
        )
    lines.extend(["    };", "  };", "};"])
    return lines


@click.group()
def host() -> None:
    """Manage hosts for Roles Anywhere."""
    pass


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
@json_option
def host_add_role(
    hostname: str,
    role_name: str,
    namespace: str,
    region: str,
    profile: str | None,
    as_json: bool,
) -> None:
    """Record that a host may assume another role.

    No new certificate is issued. A certificate carries no role information -
    it identifies the host, and which roles that host may assume is decided by
    the IAM role trust policies plus the profiles listed in the host's Nix
    configuration.

    This updates the recorded role list and prints the ARNs to add to Nix. The
    host cannot use the role until you add them there and rebuild.

    The role must live in the same scope as the host's certificate (same trust
    anchor). For cross-scope or cross-account access a host needs a second
    identity, and therefore a second certificate.

    \b
    Examples:
      iam-ra host add-role myhost readonly
      iam-ra host add-role myhost deploy --namespace prod
    """
    ctx = make_context(region, profile)
    result = handle_result(
        add_role(
            ctx,
            AddRoleConfig(namespace=namespace, hostname=hostname, role_name=role_name),
        ),
        as_json=as_json,
    )

    if as_json:
        click.echo(
            render_json(
                {
                    "hostname": result.hostname,
                    "role_name": result.role_name,
                    "already_present": result.already_present,
                    "updated_role_names": list(result.updated_role_names),
                    "role_profile": {
                        "role_name": result.role_profile.role_name,
                        "profile_arn": str(result.role_profile.profile_arn),
                        "role_arn": str(result.role_profile.role_arn),
                    },
                }
            )
        )
        return

    if result.already_present:
        click.echo(f"Role '{result.role_name}' was already recorded for '{result.hostname}'.")
    else:
        click.secho(
            f"Role '{result.role_name}' recorded for host '{result.hostname}'.",
            fg="green",
        )
    echo_key_value("Roles now recorded", ", ".join(result.updated_role_names), indent=1)

    if not result.already_present:
        click.echo()
        click.secho("Add this profile to the host's Nix configuration:", bold=True)
        click.echo()
        rp = result.role_profile
        click.echo(f"  profiles.{rp.role_name} = {{")
        click.echo(f'    profileArn = "{rp.profile_arn}";')
        click.echo(f'    roleArn    = "{rp.role_arn}";')
        click.echo("  };")


@host.command("remove-role")
@click.argument("hostname")
@click.argument("role_name")
@namespace_option
@aws_options
@json_option
def host_remove_role(
    hostname: str,
    role_name: str,
    namespace: str,
    region: str,
    profile: str | None,
    as_json: bool,
) -> None:
    """Record that a host may no longer assume a role.

    Updates the recorded role list only. You must also remove the matching
    `profiles.<name>` entry from the host's Nix configuration - until you do,
    the host can still assume the role, because authorisation comes from the IAM
    role's trust policy and the profile ARN rather than from this record.

    Refuses to remove a host's last role, since a host with none has a
    certificate but nothing to assume. Use 'iam-ra host offboard' for that.

    \b
    Examples:
      iam-ra host remove-role myhost readonly
      iam-ra host remove-role myhost deploy --namespace prod
    """
    ctx = make_context(region, profile)
    result = handle_result(
        remove_role(
            ctx,
            RemoveRoleConfig(namespace=namespace, hostname=hostname, role_name=role_name),
        ),
        as_json=as_json,
    )

    if as_json:
        click.echo(
            render_json(
                {
                    "hostname": result.hostname,
                    "role_name": result.role_name,
                    "already_absent": result.already_absent,
                    "updated_role_names": list(result.updated_role_names),
                }
            )
        )
        return

    if result.already_absent:
        click.echo(f"Role '{result.role_name}' was not recorded for '{result.hostname}'.")
    else:
        click.secho(
            f"Role '{result.role_name}' removed from host '{result.hostname}'.",
            fg="green",
        )
    echo_key_value(
        "Roles now recorded",
        ", ".join(result.updated_role_names) or "(none)",
        indent=1,
    )

    if not result.already_absent:
        click.echo()
        click.secho(
            f"Also remove `profiles.{result.role_name}` from the host's Nix "
            f"configuration - the host can still assume this role until you do.",
            fg="yellow",
        )


# =============================================================================
# v3 enrolment verbs: request / approve / enroll
#
# Distinct verbs rather than flags on `onboard`, because their preconditions
# differ - most importantly `request` needs no AWS credentials at all.
# =============================================================================


def _read_csr(csr: str) -> str:
    """Read a CSR from a file path, or from stdin when given '-'."""
    if csr == "-":
        return sys.stdin.read()
    return Path(csr).read_text()


def _write_or_echo(content: str, out: str | None, *, label: str, as_json: bool) -> None:
    """Write content to `out`, or to stdout when no path is given.

    When emitting JSON the content is carried in the payload instead, so
    printing it to stdout as well would corrupt the JSON stream.
    """
    if out is not None:
        Path(out).write_text(content)
        if not as_json:
            click.secho(f"{label} written to {out}", fg="green", err=True)
    elif not as_json:
        click.echo(content, nl=False)


@host.command("request")
@click.argument("hostname")
@namespace_option
@click.option(
    "--scope",
    "-s",
    default="default",
    show_default=True,
    help=(
        "CA scope this host will be approved under. Only affects where the key "
        "is stored locally; it cannot be looked up here because this command "
        "makes no AWS calls."
    ),
)
@click.option(
    "--key-store",
    type=click.Choice(["files", "macosKeychain"]),
    default="files",
    show_default=True,
    help="Where to generate and keep the private key.",
)
@click.option(
    "--out",
    type=click.Path(),
    default=None,
    help="Write the CSR here instead of stdout.",
)
@click.option(
    "--overwrite",
    is_flag=True,
    help="Replace an existing key for this namespace/scope.",
)
@json_option
def host_request(
    hostname: str,
    namespace: str,
    scope: str,
    key_store: str,
    out: str | None,
    overwrite: bool,
    as_json: bool,
) -> None:
    """Generate this host's private key and emit a CSR.

    Run this ON THE HOST that will use the credentials. It needs no AWS
    credentials and makes no AWS calls.

    The private key is created inside the chosen key store and never leaves it.
    Only the CSR is emitted, which is public data - paste it, commit it, or
    email it without a secure channel.

    Hand the CSR to whoever holds the CA and have them run
    `iam-ra host approve`, then install the certificate they return.

    \b
    Examples:
      iam-ra host request web01
      iam-ra host request web01 --out web01.csr
      iam-ra host request mbp --key-store macosKeychain
    """
    result = handle_result(
        request_certificate(
            RequestConfig(
                namespace=namespace,
                hostname=hostname,
                scope=scope,
                key_store=key_store,  # type: ignore[arg-type]
                overwrite=overwrite,
            )
        ),
        as_json=as_json,
    )

    if as_json:
        click.echo(
            render_json(
                {
                    "hostname": result.hostname,
                    "namespace": result.namespace,
                    "scope": result.scope,
                    "label": result.label,
                    "key_store": result.key_store,
                    "csr_pem": result.csr_pem,
                }
            )
        )
        if out is not None:
            Path(out).write_text(result.csr_pem)
        return

    click.secho("Key generated. The private key has not left this machine.", fg="green", err=True)
    echo_key_value("Hostname", result.hostname, indent=1, err=True)
    echo_key_value("Key store", result.key_store, indent=1, err=True)
    echo_key_value("Label", result.label, indent=1, err=True)
    click.echo(err=True)
    _write_or_echo(result.csr_pem, out, label="CSR", as_json=as_json)
    if out is None:
        click.echo(err=True)
    click.secho("Next: have the CA holder run", bold=True, err=True)
    click.echo(
        f"  iam-ra host approve {result.hostname} --role <role> --csr <this-csr>",
        err=True,
    )


@host.command("approve")
@click.argument("hostname")
@click.option(
    "--role",
    "-R",
    "role_flags",
    required=True,
    multiple=True,
    help="Role to grant. Repeat or comma-separate for multiple roles.",
)
@click.option(
    "--csr",
    required=True,
    help="Path to the CSR from `iam-ra host request`, or '-' for stdin.",
)
@namespace_option
@aws_options
@click.option(
    "--key-store",
    type=click.Choice(["files", "macosKeychain"]),
    default="files",
    show_default=True,
    help=(
        "What the host reported as its key store. Recorded for inventory only "
        "- it cannot be verified from a CSR and is never used for a security "
        "decision."
    ),
)
@click.option(
    "--validity-days",
    default=365,
    show_default=True,
    help="Certificate validity in days.",
)
@click.option(
    "--out",
    type=click.Path(),
    default=None,
    help="Write the signed certificate here instead of stdout.",
)
@click.option(
    "--overwrite",
    is_flag=True,
    help="Re-approve a host that already exists in state.",
)
@json_option
def host_approve(
    hostname: str,
    role_flags: tuple[str, ...],
    csr: str,
    namespace: str,
    region: str,
    profile: str | None,
    key_store: str,
    validity_days: int,
    out: str | None,
    overwrite: bool,
    as_json: bool,
) -> None:
    """Sign a host's CSR and register the host.

    Run this where the CA lives - the admin workstation for a self-signed CA,
    or anywhere with ACM Private CA access.

    The CSR is checked before signing: it must parse, its self-signature must
    verify (proving the requester holds the private key), and its key must be
    one IAM Roles Anywhere can actually use. For a self-signed CA the subject is
    rebuilt from HOSTNAME, so the CSR contributes only a public key. ACM Private
    CA copies the subject from the CSR instead, so there the CSR's CN must match
    HOSTNAME or the request is refused.

    The signed certificate is public - return it over any channel.

    \b
    Examples:
      iam-ra host approve web01 --role deploy --csr web01.csr
      iam-ra host approve web01 --role deploy --csr - < web01.csr
      iam-ra host approve mbp --role admin,readonly --csr mbp.csr --out mbp.pem
    """
    role_names: list[str] = []
    for flag in role_flags:
        for name in flag.split(","):
            name = name.strip()
            if name and name not in role_names:
                role_names.append(name)

    try:
        csr_pem = _read_csr(csr)
    except OSError as e:
        raise click.ClickException(f"Could not read CSR: {e}") from e

    ctx = make_context(region, profile)
    result = handle_result(
        approve_certificate(
            ctx,
            ApproveConfig(
                namespace=namespace,
                hostname=hostname,
                role_names=tuple(role_names),
                csr_pem=csr_pem,
                key_store=key_store,
                validity_days=validity_days,
                overwrite=overwrite,
            ),
        ),
        as_json=as_json,
    )

    if as_json:
        click.echo(
            render_json(
                {
                    "hostname": result.host.hostname,
                    "namespace": result.namespace,
                    "region": result.region,
                    "scope": result.scope,
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
                    "certificate": {
                        "serial": result.certificate.serial,
                        "not_before": result.certificate.not_before,
                        "not_after": result.certificate.not_after,
                        "subject_common_name": result.certificate.subject_common_name,
                    },
                    "certificate_pem": result.certificate_pem,
                }
            )
        )
        if out is not None:
            Path(out).write_text(result.certificate_pem)
        return

    click.secho("Certificate issued.", fg="green", err=True)
    echo_key_value("Hostname", result.host.hostname, indent=1, err=True)
    echo_key_value("Scope", result.scope, indent=1, err=True)
    echo_key_value("Roles", ", ".join(result.host.role_names), indent=1, err=True)
    echo_key_value("Serial", result.certificate.serial, indent=1, err=True)
    echo_key_value("Expires", result.certificate.not_after, indent=1, err=True)
    click.echo(err=True)
    _write_or_echo(result.certificate_pem, out, label="Certificate", as_json=as_json)
    click.echo(err=True)
    click.secho("Nix configuration for the host:", bold=True, err=True)
    click.echo(err=True)
    for line in _render_enrol_nix_snippet(
        hostname=result.host.hostname,
        scope=result.scope,
        region=result.region,
        trust_anchor_arn=str(result.trust_anchor_arn),
        role_profiles=result.role_profiles,
        credential_source=None,
    ):
        click.echo(f"  {line}", err=True)


@host.command("enroll")
@click.argument("hostname")
@click.option(
    "--role",
    "-R",
    "role_flags",
    required=True,
    multiple=True,
    help="Role to grant. Repeat or comma-separate for multiple roles.",
)
@namespace_option
@aws_options
@click.option(
    "--key-store",
    type=click.Choice(["files", "macosKeychain"]),
    default="files",
    show_default=True,
    help="Where to generate and keep the private key.",
)
@click.option(
    "--validity-days",
    default=365,
    show_default=True,
    help="Certificate validity in days.",
)
@click.option(
    "--overwrite",
    is_flag=True,
    help="Replace an existing key and re-approve the host.",
)
@json_option
def host_enroll(
    hostname: str,
    role_flags: tuple[str, ...],
    namespace: str,
    region: str,
    profile: str | None,
    key_store: str,
    validity_days: int,
    overwrite: bool,
    as_json: bool,
) -> None:
    """Generate a key, get it signed, and install the certificate - in one step.

    Use this when the machine that needs AWS credentials is also the machine
    with AWS access, which is the common case for a workstation. It is
    equivalent to `host request` followed by `host approve`, except nothing
    leaves the process.

    The private key is generated locally and is never uploaded, escrowed, or
    written anywhere but the chosen key store.

    For a host with no AWS access, use `host request` and `host approve`
    separately instead.

    \b
    Examples:
      iam-ra host enroll mbp --role admin
      iam-ra host enroll mbp --role admin,readonly --key-store macosKeychain
      iam-ra host enroll ci --role deploy --validity-days 7
    """
    role_names: list[str] = []
    for flag in role_flags:
        for name in flag.split(","):
            name = name.strip()
            if name and name not in role_names:
                role_names.append(name)

    ctx = make_context(region, profile)
    result = handle_result(
        enrol_host(
            ctx,
            EnrolConfig(
                namespace=namespace,
                hostname=hostname,
                role_names=tuple(role_names),
                key_store=key_store,  # type: ignore[arg-type]
                validity_days=validity_days,
                overwrite=overwrite,
            ),
        ),
        as_json=as_json,
    )

    approve = result.approve
    nix_lines = _render_enrol_nix_snippet(
        hostname=approve.host.hostname,
        scope=approve.scope,
        region=approve.region,
        trust_anchor_arn=str(approve.trust_anchor_arn),
        role_profiles=approve.role_profiles,
        credential_source=result.credential_source,
    )

    if as_json:
        match result.credential_source:
            case FileCredentialSource(certificate_path, private_key_path):
                source_payload: dict[str, object] = {
                    "kind": "files",
                    "certificate_path": str(certificate_path),
                    "private_key_path": str(private_key_path),
                }
            case KeychainCredentialSource(subject_common_name, keychain_path):
                source_payload = {
                    "kind": "macosKeychain",
                    "subject_common_name": subject_common_name,
                    "keychain_path": str(keychain_path),
                }
        click.echo(
            render_json(
                {
                    "hostname": approve.host.hostname,
                    "namespace": approve.namespace,
                    "region": approve.region,
                    "scope": approve.scope,
                    "role_names": list(approve.host.role_names),
                    "key_store": result.key_store,
                    "label": result.label,
                    "trust_anchor_arn": str(approve.trust_anchor_arn),
                    "role_profiles": [
                        {
                            "role_name": rp.role_name,
                            "profile_arn": str(rp.profile_arn),
                            "role_arn": str(rp.role_arn),
                        }
                        for rp in approve.role_profiles
                    ],
                    "certificate": {
                        "serial": approve.certificate.serial,
                        "not_after": approve.certificate.not_after,
                    },
                    "credential_source": source_payload,
                    "nix_snippet": "\n".join(nix_lines),
                }
            )
        )
        return

    click.secho("Enrolled.", fg="green", bold=True)
    click.echo()
    echo_key_value("Hostname", approve.host.hostname, indent=1)
    echo_key_value("Namespace", approve.namespace, indent=1)
    echo_key_value("Scope", approve.scope, indent=1)
    echo_key_value("Roles", ", ".join(approve.host.role_names), indent=1)
    echo_key_value("Key store", result.key_store, indent=1)
    echo_key_value("Serial", approve.certificate.serial, indent=1)
    echo_key_value("Expires", approve.certificate.not_after, indent=1)

    click.echo()
    click.secho("Add this to your Nix configuration:", bold=True)
    click.echo()
    for line in nix_lines:
        click.echo(f"  {line}")

    click.echo()
    click.secho("Then rebuild and verify:", bold=True)
    click.echo()
    for rp in approve.role_profiles:
        click.echo(f"  aws sts get-caller-identity --profile {rp.role_name}")
