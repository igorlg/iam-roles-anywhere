# Migrating to v3

> **Status: in development.** v3 is being built on the `v3` branch and is not yet released.
> This document is updated as each change lands. Do not follow it against a v2 release.

## Why v3 is a breaking change

In v2, host private keys are generated on the **admin workstation** and shipped to the host:

```
admin (keygen) -> S3 -> Fetcher Lambda -> CloudFormation -> Secrets Manager -> SOPS file -> host
```

The key therefore exists in at least five places, permanently, and anyone with
`secretsmanager:GetSecretValue` can impersonate any host.

In v3, the private key is **generated on the host and never leaves it**. Only the CSR and the signed
certificate move, and both are public data.

This is not a change that can be made compatibly, so **v3 requires re-enrolling every host.**

## Summary of breaking changes

| Area | v2 | v3 |
|---|---|---|
| Host key generation | admin workstation | on the host |
| Key in S3 / Secrets Manager | yes | **no** |
| Host CloudFormation stack | `iam-ra-<ns>-host-<host>` | **removed** |
| SOPS file for cert/key | required | **not required** (cert is public, commit it in plain Nix) |
| Host onboarding command | `iam-ra host onboard` | `iam-ra host enroll` (one-shot) or `host request` + `host approve` (split) |
| `iam-ra host rotate-cert` | rotated the key from the admin box | **removed** — rotation is now a host-side re-enrol |
| `iam-ra host add-role` / `remove-role` | updated state *and* rewrote the SOPS file | update state only; you edit Nix yourself |
| State schema | v3 | v4 |
| Nix `certificate` options | `certPath` + `keyPath` | tagged union with `source = "files" \| "macosKeychain" \| ...` |
| Nix lib credential helpers | `certificatePath` + `privateKeyPath` args | single `certificate` arg (the tagged union) |
| Role trust policy | trust anchor only | optional per-host CN condition |

## Nix module: certificate options

`certificate.source` was added, defaulting to `"files"`. **Existing configurations that set
`certPath` and `keyPath` continue to work unchanged** — all the shipped examples still evaluate.

`certPath` and `keyPath` are now nullable and required only when `source = "files"`. New assertions
reject incoherent combinations, so configs that would have failed at runtime now fail at eval:

- `source = "files"` without `certPath`/`keyPath`
- `source = "files"` with a `selector` set (it would otherwise be silently ignored)
- `source = "macosKeychain"` with no selector field set (would match every keychain identity)
- `source = "macosKeychain"` combined with `certPath`/`keyPath` — `aws_signing_helper` treats
  `--cert-selector` as mutually exclusive with `--certificate` and `--private-key`
- `source = "macosKeychain"` on a non-Darwin system — the credential helper's certificate-store
  support is a stub that returns an error at runtime on Linux

### Breaking: `iam-ra.lib` credential-process helpers

If you call these directly (most users do not — the module does it for you), the certificate
arguments moved into a single `certificate` attrset:

```nix
# v2
iam-ra.lib.mkCredentialProcessCommand {
  certificatePath = "/path/cert.pem";
  privateKeyPath  = "/path/key.pem";
  # ...
}

# v3
iam-ra.lib.mkCredentialProcessCommand {
  certificate = { source = "files"; certPath = "/path/cert.pem"; keyPath = "/path/key.pem"; };
  # ...
}
```

The inline `credential_process` command now passes every argument through `lib.escapeShellArg`.
This fixes a latent bug: a certificate path containing a space previously produced a broken command
in the inline form, while the wrapper-script form quoted correctly. Plain paths and ARNs are
unaffected, since `escapeShellArg` leaves metacharacter-free tokens alone.

## State schema v4

`State.hosts[<name>]` changed shape. **No migration step is required** — v3 state documents load
unchanged, because the fields that v4 stops populating simply became optional.

Added, for hosts enrolled with a host-generated key:

| Field | Meaning |
|---|---|
| `key_store` | Which KeyStore holds the private key (`files`, `macosKeychain`). `null` for v2/v3 hosts. |
| `certificate_serial` | Uppercase hex, **no leading zeros** — the form `--cert-selector x509Serial` expects. Note this differs from `openssl x509 -serial`, which zero-pads. |
| `not_after` | ISO 8601 expiry, so `iam-ra status` can warn about ageing certificates. |

Now optional, and `null` for v4 hosts:

| Field | Why |
|---|---|
| `stack_name` | v4 hosts have no per-host CloudFormation stack. |
| `certificate_secret_arn` | The certificate is not escrowed in Secrets Manager. |
| `private_key_secret_arn` | The private key never leaves the host. |

A host with `key_store == null` and a `private_key_secret_arn` is reported as
`legacy_managed_key: true` by `iam-ra status --json`. Those hosts keep working, but their private
key exists in several places outside the host; re-enrolling replaces it with a host-generated key.

`iam-ra host offboard` and `iam-ra destroy` now skip CloudFormation and S3 cleanup for hosts with no
`stack_name`, since there is nothing in AWS to tear down.

## The new commands

```bash
# One machine — the common case for a workstation with AWS access.
iam-ra host enroll mbp --role admin --role readonly

# Two machines — a server with no AWS credentials.
#   on the host (needs NO AWS credentials at all):
iam-ra host request web01 --out web01.csr
#   wherever the CA lives:
iam-ra host approve web01 --role deploy --csr web01.csr --out web01.pem
#   back on the host: install web01.pem and point Nix at it
```

Both the CSR and the signed certificate are public, so they need no confidential channel — paste
them, commit them to your Nix config repo, or send them over email. Compare this with v2, which
required transporting a *private key* to the host.

What each verb checks before signing:

- the CSR parses
- its self-signature verifies, proving the requester holds the private key (proof of possession)
- its key is one IAM Roles Anywhere can actually use — RSA ≥ 2048 or EC P-256/384/521; Ed25519,
  Ed448 and DSA are refused because the credential helper cannot sign a CreateSession request with
  them, so the certificate would be inert

The two CA backends differ in how much of the CSR they trust, and it is worth knowing which you are
on:

| CA mode | Subject handling |
|---|---|
| self-signed | The subject is **rebuilt** from the hostname you approve. The CSR contributes only a public key, so a host cannot obtain a certificate naming a different host. |
| ACM Private CA | PCA copies the subject from the CSR and the client-auth template does not allow an override, so `approve` instead **verifies** the CSR's CN matches and refuses on mismatch. |

## Removed commands

### `iam-ra host onboard`

Replaced by `host enroll`, or `host request` + `host approve`. The only reason `onboard` could work
was that the admin machine generated the host's private key, which is exactly what v3 removes.

### `iam-ra host rotate-cert`

Removed with no direct replacement, because it rotated a host's key **from the admin workstation** —
possible only while the admin holds that key. Under v3 the key lives on the host and never leaves,
so rotation is necessarily a host-side action:

```bash
# on the host, one machine:
iam-ra host enroll <hostname> --role <role> --overwrite

# split:
iam-ra host request <hostname> --overwrite --out new.csr
iam-ra host approve <hostname> --role <role> --csr new.csr --overwrite --out new.pem
```

Note the old certificate remains valid until it expires — there is no revocation in either version.

### `iam-ra host add-role` / `remove-role` behaviour changed

They no longer rewrite a SOPS file, because there isn't one. A certificate carries no role
information: it identifies the host, and which roles that host may assume is decided by the IAM role
trust policies plus the `profiles.<name>` entries in the host's Nix configuration.

So these commands now update the *recorded* role list and print the ARNs to paste into Nix.
`--sops-output` is gone from both.

**This means `remove-role` alone does not revoke access.** Until you remove the matching
`profiles.<name>` entry from Nix and rebuild, the host can still assume the role. The command warns
about this.

## Migration path

Re-enrolment. There is no in-place upgrade.

<!-- TODO: fill in concrete steps as each task lands.
     Required content:
       1. inventory existing hosts (`iam-ra host list`)
       2. offboard, or run v2 and v3 side by side during transition
       3. per-host: `iam-ra host enroll` (or request/approve)
       4. update Nix config to the new certificate option shape
       5. remove now-unnecessary sops.secrets entries for cert/key
       6. verify with `aws sts get-caller-identity --profile <name>`
       7. clean up: delete v2 host stacks and Secrets Manager secrets
     Also document:
       - state schema v3 -> v4 auto-migration behaviour
       - what happens to certs issued under v2 (still valid until expiry; no revocation exists)
-->

## Notes carried over from design

- Certificates issued under v2 remain valid against the trust anchor until they expire. There is no
  revocation mechanism in either version, so **offboarding a host does not invalidate its
  certificate**. Keep this in mind when planning the cutover.
- The `--cert-selector` used by the macOS Keychain backend is mutually exclusive with
  `--certificate` / `--private-key` in `aws_signing_helper`, which is why the Nix options become a
  tagged union rather than gaining extra optional fields.
