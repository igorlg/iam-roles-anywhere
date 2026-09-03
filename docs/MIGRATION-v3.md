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
| State schema | v3 | v4 |
| Nix `certificate` options | `certPath` + `keyPath` | tagged union with `source = "files" \| "macosKeychain" \| ...` |
| Role trust policy | trust anchor only | optional per-host CN condition |

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
