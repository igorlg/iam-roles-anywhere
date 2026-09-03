# Migrating to v3

> **Status: in development.** v3 is being built on the `v3` branch and is not yet released.
> This document is updated as each change lands. Do not follow it against a v2 release.

## Why v3 is a breaking change

In v2, host private keys are generated on the **admin workstation** and shipped to the host:

```text
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
| Host onboarding command | `iam-ra host onboard` | `iam-ra host enroll` (one-shot) or `host request` + `host approve` + `host install` (split) |
| `iam-ra host rotate-cert` | rotated the key from the admin box | **removed** — rotation is now a host-side re-enrol |
| `iam-ra host add-role` / `remove-role` | updated state *and* rewrote the SOPS file | update state only; you edit Nix yourself |
| State schema | v3 | v4 |
| Nix `certificate` options | `certPath` + `keyPath` | tagged union with `source = "files" \| "macosKeychain" \| ...` |
| Nix lib credential helpers | `certificatePath` + `privateKeyPath` args | single `certificate` arg (the tagged union) |
| Role trust policy | trust anchor only | optional per-host CN condition via `--allowed-hosts` (default unchanged) |

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
#   back on the host, again with no AWS credentials:
iam-ra host install web01 --certificate web01.pem
```

Both the CSR and the signed certificate are public, so they need no confidential channel — paste
them, commit them to your Nix config repo, or send them over email. Compare this with v2, which
required transporting a *private key* to the host.

Four verbs rather than flags on one command, because their preconditions genuinely differ:

| Verb | Runs where | Needs AWS | Touches the private key |
|---|---|---|---|
| `request` | on the host | no | creates it, in the key store |
| `approve` | wherever the CA lives | yes | never sees it |
| `install` | on the host | no | pairs a certificate with it |
| `enroll` | on a host that has AWS access | yes | all three of the above, in one process |

`request` and `install` take no AWS context *in their function signatures*, not merely by
convention — a test asserts this, so a future refactor cannot quietly reintroduce a credential
requirement on the host side.

`install` refuses a certificate whose public key does not match the key the host is holding. That
catches the two realistic mistakes: a certificate meant for a different host, and a certificate
superseded by a later `request` that rotated the key. Both would otherwise produce a cert/key pair
that fails at credential time with no useful diagnostic.

What `approve` checks before signing:

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

Replaced by `host enroll`, or `host request` + `host approve` + `host install`. The only reason `onboard` could work
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

Note the old certificate remains valid until it expires. See [Revocation](#revocation) below — it is possible, but this tool does not do it for you.

### `iam-ra host add-role` / `remove-role` behaviour changed

They no longer rewrite a SOPS file, because there isn't one. A certificate carries no role
information: it identifies the host, and which roles that host may assume is decided by the IAM role
trust policies plus the `profiles.<name>` entries in the host's Nix configuration.

So these commands now update the *recorded* role list and print the ARNs to paste into Nix.
`--sops-output` is gone from both.

**This means `remove-role` alone does not revoke access.** Until you remove the matching
`profiles.<name>` entry from Nix and rebuild, the host can still assume the role. The command warns
about this.

## Key stores

`--key-store` chooses where the host's private key lives.

| Backend | Platform | Key protection |
|---|---|---|
| `files` (default) | any | PEM on disk, `0600` in a `0700` directory. Never transmitted, never escrowed — but readable by anyone who can read the file. |
| `macosKeychain` | macOS only | Non-extractable key in a dedicated keychain. Cannot be copied off the machine, even by a process running as you. |

```bash
iam-ra host enroll mbp --role admin --key-store macosKeychain
```

### What `macosKeychain` actually protects against

The key is imported with `security import -x`, so the Security framework refuses to export it. An
attacker with code execution as your user can still *use* it — but they could get AWS credentials by
running `aws` anyway. What they cannot do is take the key with them for offline or later use. That
is the whole difference from `files`, and it is a meaningful one against backup theft, stolen disk
images, and snapshot exfiltration.

It is deliberately imported with `-A` (any application may use it) rather than `-T` (only a named
binary). A `-T` ACL sounds stronger but is not: the nix-built `aws_signing_helper` is ad-hoc signed
with no Team ID, so macOS identifies it by content hash, and **every rebuild would invalidate the ACL
and turn each `aws` command into an interactive password prompt**. The ACL also restricts only
*which binary* may use the key, while any process running as you can simply execute that binary. So
it costs reliability and buys close to nothing.

### Operational notes

- One keychain per machine at `~/Library/Keychains/iam-ra.keychain`, holding one identity per host,
  selected by certificate subject.
- Its password is generated randomly and stored in your **login keychain**, so it is protected by
  your login password and FileVault rather than sitting in a file.
- The keychain is added to your keychain search list (existing entries are preserved — the
  credential helper only searches listed keychains) and `set-keychain-settings` disables the default
  ~5 minute auto-relock, which would otherwise break credential fetches after enrolment.
- Certificates chain to your own CA, not a system trust anchor, so `security find-identity -v` reports
  zero identities and `find-identity` shows `CSSMERR_TP_NOT_TRUSTED`. This is expected and harmless:
  IAM Roles Anywhere validates against its trust anchor server-side.
- `iam-ra host offboard` cannot remove a key whose certificate was never installed — `security` has
  no command to delete a bare private key. Such a key is inert: non-extractable, and unusable without
  a certificate to select it.

## Per-host role restriction

`iam-ra role create` gained `--allowed-hosts`.

Previously — and still, by default — a role's trust policy conditioned only on the trust anchor, so
**any** certificate under a scope's CA could assume **any** role in that scope. Scope was the only
isolation boundary. Now you can narrow a role to specific hosts:

```bash
iam-ra role create deploy --policy arn:... --allowed-hosts 'ci-*'
iam-ra role create admin  --policy arn:... --allowed-hosts mbp
```

This adds a `StringLike` condition on `aws:PrincipalTag/x509Subject/CN`, which IAM Roles Anywhere
populates from the authenticating certificate's subject. It is additive: the `aws:SourceArn`
trust-anchor pin remains, so removing the confused-deputy protection is not possible by using this.

**The default is unchanged and unrestricted.** With `--allowed-hosts '*'` (the default) the condition
is omitted from the policy entirely rather than written as a wildcard match. That is deliberate: a
`StringLike` condition on an *absent* principal tag evaluates false, so emitting a wildcard by default
would make every role depend on the tag being present and could deny access to anyone whose profile
drops it. Upgrading therefore cannot change who may assume an existing role.

Two caveats worth knowing:

- This only becomes a real per-host boundary once keys are host-generated. Under v2 the admin held
  every host's key, so any host's identity could be reproduced.
- If you attach custom `attributeMappings` to a Roles Anywhere profile and omit the Subject CN
  specifier, the tag is dropped and a restricted role becomes unassumable. `iam-ra` sets no attribute
  mappings, so the default mapping applies.

`iam-ra status --json` reports `allowed_subject_cn` per role, so unrestricted roles are auditable.

## Revocation

Neither v2 nor v3 revokes certificates, and `host offboard` does not either — it removes the host
from state and tears down its AWS resources, but an already-issued certificate keeps authenticating
until it expires.

This is a gap in **this tool**, not in IAM Roles Anywhere. The service does support revocation, by
importing a CRL generated from your CA via its
[`ImportCrl` API](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/trust-model.html);
certificates are then checked against it. What the service does *not* support is fetching CRLs from a
distribution point or querying OCSP, so the CRL has to be pushed to it explicitly.

Until `iam-ra` manages CRLs, the practical mitigation is short certificate lifetimes:

```bash
iam-ra host enroll web01 --role deploy --validity-days 7
```

That bounds the exposure window for a compromised or offboarded host to the remaining validity, which
is why v3 makes re-enrolment cheap enough to run on a timer.

## Migration path

Re-enrolment. There is no in-place upgrade, because the whole point of v3 is that the private key is
generated somewhere v2 could not reach — on the host. No amount of state rewriting produces a key
that was never escrowed.

The good news is that the migration is **incremental and non-disruptive**. Your namespace, trust
anchors, CA and roles are all untouched by v3; only the per-host key and certificate change. A v2
host and a v3 host can coexist under the same trust anchor indefinitely, so you can migrate one host
at a time and roll back a single host without affecting any other.

Nothing about the state file needs preparing: v3 state documents load into v4 unchanged (see
[State schema v4](#state-schema-v4)). Upgrading the CLI is safe on its own.

### 0. Upgrade the CLI, then take an inventory

```bash
iam-ra --version          # expect 3.x
iam-ra host list
iam-ra status --json | jq '.hosts'
```

Hosts reported with `legacy_managed_key: true` are the ones to migrate — their private key was
generated on the admin workstation and still exists in S3, Secrets Manager and your SOPS files.

### 1. Re-enrol one host

Pick the migration flow that matches the host:

**The host has AWS credentials** (typical for a workstation) — one command, on the host:

```bash
iam-ra host enroll web01 --role deploy --overwrite
```

**The host has no AWS access** (typical for a server or CI box) — two commands, two machines:

```bash
# On the host. Needs no AWS credentials, makes no AWS calls.
iam-ra host request web01 --out web01.csr

# Copy web01.csr to the admin workstation. It is public data - email it,
# paste it, commit it. There is no secure channel to arrange.
iam-ra host approve web01 --role deploy --csr web01.csr --out web01.pem --overwrite

# Copy web01.pem back to the host and install it. Also public data.
iam-ra host install web01 --certificate web01.pem
```

`--overwrite` is required for both, since the host already exists in state from v2. It replaces the
recorded certificate; it does **not** revoke the old one (see [Revocation](#revocation)).

Add `--key-store macosKeychain` on macOS to get a non-extractable key. See [Key stores](#key-stores).

### 2. Update that host's Nix configuration

Both commands print the exact snippet to paste. The shape changes from a flat `certPath`/`keyPath`
pair to a tagged union under `certificate.source` — see
[Nix module: certificate options](#nix-module-certificate-options) for the full option reference.

For `--key-store files`:

```nix
programs.iamRolesAnywhere = {
  enable = true;
  identities.default = {
    certificate = {
      source   = "files";
      certPath = "/Users/alice/.local/state/iam-ra/keys/default-default/cert.pem";
      keyPath  = "/Users/alice/.local/state/iam-ra/keys/default-default/key.pem";
    };
    trustAnchorArn = "arn:aws:rolesanywhere:...";
    region = "ap-southeast-2";
    profiles.deploy = { profileArn = "..."; roleArn = "..."; };
  };
};
```

For `--key-store macosKeychain`:

```nix
certificate = {
  source = "macosKeychain";
  selector.subject = "CN=web01";
};
```

Then rebuild as usual (`nixos-rebuild switch`, `darwin-rebuild switch`, or `home-manager switch`).

### 3. Drop the SOPS wiring for that host

This is the step that pays for the migration. Delete the cert and key entries:

```nix
# DELETE - v3 has nothing to decrypt here.
sops.secrets."iam-ra/cert".sopsFile = ./secrets/hosts/web01/iam-ra-default.yaml;
sops.secrets."iam-ra/key".sopsFile  = ./secrets/hosts/web01/iam-ra-default.yaml;
```

The certificate is public and is now referenced by a plain path, and the private key never leaves the
host. Once the host is verified, delete the SOPS file itself:

```bash
git rm secrets/hosts/web01/iam-ra-default.yaml
```

Note that deleting the file does not un-leak the key it held. Anything with a copy of that repo, or
of its history, still has the v2 key. That key is only truly retired once the certificate it belongs
to has expired or been placed on an imported CRL.

### 4. Verify

```bash
aws sts get-caller-identity --profile deploy
```

You should see the role ARN and, in `UserId`, the certificate serial. To check what identity the
credential helper actually selected:

```bash
# files backend
openssl x509 -in ~/.local/state/iam-ra/keys/default-default/cert.pem -noout -subject -dates

# macosKeychain backend
security find-identity ~/Library/Keychains/iam-ra.keychain
```

If this fails, the host's v2 configuration is still intact until you complete step 5 — revert the Nix
change and rebuild to roll back.

### 5. Tear down the v2 AWS resources for that host

Only once the host is verified. v2 left a per-host CloudFormation stack, S3 objects and Secrets
Manager secrets; v3 creates none of these.

```bash
aws cloudformation delete-stack --stack-name iam-ra-default-host-web01
```

`iam-ra host offboard` is not the right tool here: it also removes the host from state, and you want
the host to stay. Delete the stack directly. It owns the Secrets Manager secrets and is the only
thing that referenced the S3 objects, so removing it cleans up both.

Confirm nothing is left holding the old key:

```bash
aws secretsmanager list-secrets \
  --query "SecretList[?starts_with(Name, '/iam-ra/default/hosts/web01')].Name"
```

### 6. Repeat, then confirm the namespace is clean

```bash
iam-ra status --json | jq '[.hosts[] | select(.legacy_managed_key == true) | .hostname]'
```

An empty array means every host now holds a key that was generated in place and has never been
transmitted. At that point the v2 key-escrow chain described in
[Why v3 is a breaking change](#why-v3-is-a-breaking-change) no longer exists anywhere in your
deployment.

### What about certificates issued under v2?

They remain valid against the trust anchor until they expire. Re-enrolling a host does not invalidate
its old certificate, and neither does offboarding it or deleting its stack — so during migration a
host legitimately has two working certificates, and an attacker holding a leaked v2 key has one too.

Close that window in one of two ways: import a CRL covering the old certificates, or wait out their
validity (365 days by default, which is why v3 recommends far shorter lifetimes). See
[Revocation](#revocation).

## Notes carried over from design

- Certificates issued under v2 remain valid against the trust anchor until they expire, so
  **offboarding a host does not by itself invalidate its certificate**. See
  [Revocation](#revocation). Keep this in mind when planning the cutover.
- The `--cert-selector` used by the macOS Keychain backend is mutually exclusive with
  `--certificate` / `--private-key` in `aws_signing_helper`, which is why the Nix options become a
  tagged union rather than gaining extra optional fields.
