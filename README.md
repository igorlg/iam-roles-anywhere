# IAM Roles Anywhere - Nix Flake

Certificate-based AWS authentication for Nix hosts and Kubernetes using [AWS IAM Roles Anywhere](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.html).

> **v3 is a breaking change.** Host private keys are now generated on the host
> and never transmitted. If you are upgrading from v2, read
> [docs/MIGRATION-v3.md](docs/MIGRATION-v3.md) — migration is per-host and
> non-disruptive, but it is not automatic.

## Overview

This flake provides three components:

### 1. Nix Modules (Runtime - installed on hosts)

Configures hosts to **use** IAM Roles Anywhere for AWS authentication:

- `aws-signing-helper` - credential process for IAM Roles Anywhere
- `~/.aws/config` - configured with `credential_process`
- **Multi-profile support** - one host can assume multiple roles
- Certificate sources are pluggable - plain files, or a macOS keychain

### 2. `iam-ra` CLI (Admin Tool)

A CLI for **managing** IAM Roles Anywhere infrastructure:

- Initialize AWS infrastructure (CloudFormation stacks)
- Create roles with Roles Anywhere profiles, optionally restricted to named hosts
- Enrol hosts by signing a CSR the host generated itself
- **Onboard Kubernetes workloads** (generate cert-manager manifests)

### 3. Kubernetes Integration

Generate manifests for Kubernetes workloads to use IAM Roles Anywhere:

- cert-manager Issuer and Certificate resources
- Sidecar-based credential delivery
- Works with any K8s cluster (on-prem, self-managed, EKS)

```text
┌─────────────────────────────────────────────────────────────────┐
│                        ADMIN WORKSTATION                        │
│  ┌───────────────┐                                              │
│  │   iam-ra CLI  │  ← Manages AWS infrastructure                │
│  │               │    - iam-ra init                             │
│  │               │    - iam-ra role create <name>               │
│  │               │    - iam-ra host approve <hostname>  (signs) │
│  │               │    - iam-ra k8s setup <cluster>              │
│  │               │    - iam-ra k8s onboard <workload>           │
│  └───────────────┘                                              │
│         ▲ CSR (public)          certificate (public) ▼          │
└─────────┼───────────────────────────────────────────┼───────────┘
          │                                           │
┌─────────┼───────────────────────────────────────────┼───────────┐
│         │            NIX HOSTS                      ▼           │
│  ┌───────────────┐                                              │
│  │   iam-ra CLI  │  ← iam-ra host request  (generates the key)  │
│  │               │    iam-ra host install  (pairs the cert)     │
│  ├───────────────┤                                              │
│  │  Nix Modules  │  ← Uses IAM Roles Anywhere                   │
│  │               │    - aws-signing-helper                      │
│  │               │    - ~/.aws/config (multi-profile)           │
│  └───────────────┘                                              │
│  Private key stays here. Always.                                │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                      KUBERNETES CLUSTERS                        │
│  ┌───────────────┐                                              │
│  │  cert-manager │  ← Issues certificates                       │
│  │  + sidecar    │  ← aws_signing_helper serves credentials     │
│  └───────────────┘                                              │
└─────────────────────────────────────────────────────────────────┘
```

Only two things ever cross that boundary: a **CSR** and a **certificate**. Both
are public, so neither needs a secure channel, a secrets manager, or encryption
at rest. See [SECURITY.md](SECURITY.md) for the threat model.

## Quick Start

### 1. Initialize Infrastructure (once per namespace)

```bash
nix run github:igorlg/iam-roles-anywhere -- init
```

### 2. Create Roles

```bash
iam-ra role create admin --policy arn:aws:iam::aws:policy/AdministratorAccess
iam-ra role create readonly --policy arn:aws:iam::aws:policy/ReadOnlyAccess
```

### 3. Enrol a Host

Pick the flow that matches the machine.

**The machine has AWS access** (typical for your own workstation) - one command:

```bash
iam-ra host enroll mbp --role admin
```

**The machine has no AWS access** (typical for a server or CI runner) - three
commands across two machines:

```bash
# On the host. Needs NO AWS credentials and makes no AWS calls.
iam-ra host request web01 --out web01.csr

# Anywhere with CA access. The CSR is public - email it, paste it, commit it.
iam-ra host approve web01 --role deploy --csr web01.csr --out web01.pem

# Back on the host. The certificate is public too.
iam-ra host install web01 --certificate web01.pem
```

Either way the private key is created inside the host's key store and never
leaves it. There is no key to copy, encrypt, or lose.

On macOS, add `--key-store macosKeychain` to `request`/`install` (or to
`enroll`) to keep the key in a keychain and mark it **non-extractable** - it
then cannot be copied off the host even by a process running as you.

### 4. Configure Host in Nix

Every enrolment command prints the exact snippet. For the `files` key store:

```nix
{ inputs, ... }:
{
  imports = [ inputs.iam-roles-anywhere.nixosModules.default ];

  programs.iamRolesAnywhere = {
    enable = true;
    user = "alice";

    # Single identity; for cross-account see examples/hosts/multi-identity.nix
    identities.default = {
      # Where this host's certificate and key live.
      certificate = {
        source   = "files";
        certPath = "/home/alice/.local/state/iam-ra/keys/default-default/cert.pem";
        keyPath  = "/home/alice/.local/state/iam-ra/keys/default-default/key.pem";
      };

      # Identity-level AWS config
      trustAnchorArn = "arn:aws:rolesanywhere:ap-southeast-2:123456789012:trust-anchor/...";
      region = "ap-southeast-2";

      # Multiple profiles - one host can assume different roles
      profiles = {
        admin = {
          profileArn = "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/admin";
          roleArn = "arn:aws:iam::123456789012:role/admin";
          makeDefault = true;  # Also creates [default] profile
        };
        readonly = {
          profileArn = "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/readonly";
          roleArn = "arn:aws:iam::123456789012:role/readonly";
        };
      };
    };
  };
}
```

No SOPS or agenix wiring is needed for the certificate. It is public data, so a
plain path is correct - and the private key is not referenced by your Nix config
at all, because it never left the host.

For the `macosKeychain` key store, replace the `certificate` block with:

```nix
certificate = {
  source = "macosKeychain";
  selector.subject = "CN=mbp";
};
```

### 5. Use AWS CLI

```bash
# Uses the default profile (admin in this example)
aws sts get-caller-identity

# Or specify a profile
aws sts get-caller-identity --profile admin
aws sts get-caller-identity --profile readonly
```

## Installation

### Flake Input

```nix
{
  inputs.iam-roles-anywhere.url = "github:igorlg/iam-roles-anywhere";

  outputs = { self, nixpkgs, iam-roles-anywhere, ... }: {
    # NixOS
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      modules = [
        iam-roles-anywhere.nixosModules.default
        ./configuration.nix
      ];
    };

    # Darwin
    darwinConfigurations.myhost = darwin.lib.darwinSystem {
      modules = [
        iam-roles-anywhere.darwinModules.default
        ./configuration.nix
      ];
    };

    # Home Manager (standalone)
    homeConfigurations.alice = home-manager.lib.homeManagerConfiguration {
      modules = [
        iam-roles-anywhere.homeModules.default
        ./home.nix
      ];
    };
  };
}
```

### CLI

```bash
# Run directly
nix run github:igorlg/iam-roles-anywhere -- --help

# Or add to devShell
nix develop github:igorlg/iam-roles-anywhere
iam-ra --help
```

The CLI is needed on hosts too, for `host request` and `host install`. Those two
subcommands make no AWS calls and need no credentials.

## CLI Commands

```text
iam-ra [OPTIONS] COMMAND

Commands:
  init      Initialize IAM Roles Anywhere infrastructure
  destroy   Tear down all infrastructure for a namespace
  status    Show current status
  migrate   Bring a namespace up to the current schema + file layout
  ca        Manage per-scope Certificate Authorities
    setup     Create a CA scope (CA + trust anchor)
    list      List CA scopes
    delete    Delete a CA scope
  role      Manage IAM roles
    create  Create role with Roles Anywhere profile
    delete  Delete role
    list    List all roles
  host      Manage hosts
    request      Generate this host's key, emit a CSR   (on the host, no AWS)
    approve      Sign a CSR and register the host       (where the CA lives)
    install      Install the signed certificate         (on the host, no AWS)
    enroll       All three at once                      (host with AWS access)
    add-role     Record that a host may assume another role
    remove-role  Record that a host may no longer assume a role
    offboard     Remove host from state and tear down legacy AWS resources
    list         List all hosts
  k8s       Manage Kubernetes integration
    setup     Set up cluster (CA + Issuer)
    teardown  Remove cluster from state
    onboard   Onboard workload (Certificate + Pod)
    offboard  Remove workload from state
    list      List clusters and workloads
```

### Host Examples

```bash
# Initialize with self-signed CA (default)
iam-ra init

# Initialize with AWS Private CA
iam-ra init --ca-mode pca-new

# Create roles
iam-ra role create admin --policy arn:aws:iam::aws:policy/AdministratorAccess
iam-ra role create deploy --policy arn:aws:iam::123:policy/DeployPolicy --session-duration 7200

# Restrict a role to specific hosts (matched on certificate subject CN)
iam-ra role create deploy --policy arn:... --allowed-hosts 'ci-*'

# Enrol a workstation that has AWS access
iam-ra host enroll mbp --role admin
iam-ra host enroll mbp --role admin,readonly --key-store macosKeychain

# Short-lived certificate, so a compromise expires quickly
iam-ra host enroll ci --role deploy --validity-days 7

# Enrol a host with no AWS access
iam-ra host request web01 --out web01.csr                       # on the host
iam-ra host approve web01 --role deploy --csr web01.csr \
  --out web01.pem                                               # at the CA
iam-ra host install web01 --certificate web01.pem               # on the host

# Rotate: same commands with --overwrite
iam-ra host enroll mbp --role admin --overwrite

# Grant an extra role (then add the printed ARNs to the host's Nix config)
iam-ra host add-role web01 readonly

# Check status
iam-ra status
iam-ra status --json

# Clean up
iam-ra host offboard web01
iam-ra role delete deploy
iam-ra destroy --yes
```

Piping works throughout, so the split flow can skip intermediate files:

```bash
ssh web01 iam-ra host request web01 \
  | iam-ra host approve web01 --role deploy --csr - \
  | ssh web01 iam-ra host install web01 --certificate -
```

### Kubernetes Examples

```bash
# Set up a K8s cluster (once per cluster)
iam-ra k8s setup prod-cluster | kubectl apply -f -

# Onboard workloads
iam-ra k8s onboard payment-service --role admin --cluster prod-cluster | kubectl apply -f -
iam-ra k8s onboard api-gateway --role readonly --cluster prod-cluster -k gateway | kubectl apply -f -

# List K8s resources
iam-ra k8s list
iam-ra k8s list --cluster prod-cluster

# Clean up
iam-ra k8s offboard payment-service
iam-ra k8s teardown prod-cluster
```

See [docs/KUBERNETES.md](docs/KUBERNETES.md) for detailed Kubernetes documentation.

## Key Stores

`--key-store` selects where a host's private key is generated and kept. The key
is created inside the store and is never written anywhere else.

| Backend | Platforms | Key readable by | Notes |
|---|---|---|---|
| `files` (default) | all | anyone who can read the file | `0600` file in a `0700` directory under `$XDG_STATE_HOME/iam-ra/keys/<ns>-<scope>/` |
| `macosKeychain` | macOS only | nothing - marked non-extractable | Key cannot be exported even by you; the credential helper signs through the keychain |

Both are a substantial improvement on v2, where the key was generated on the
admin workstation and copied to S3, Secrets Manager, and a SOPS file. `files`
removes the transmission and the escrow. `macosKeychain` additionally removes
the ability to read the key at all.

Choosing `macosKeychain` changes the Nix `certificate` block from a pair of
paths to a selector, because `aws_signing_helper` treats `--cert-selector` as
mutually exclusive with `--certificate`/`--private-key`:

```nix
certificate = {
  source = "macosKeychain";
  selector.subject = "CN=mbp";   # or selector.issuer / selector.serial
};
```

Operational notes for `macosKeychain`:

- One keychain per machine at `~/Library/Keychains/iam-ra.keychain`, holding as
  many host identities as you enrol, each selected by certificate subject.
- The keychain password is generated and stored in your login keychain, so
  unlocking is automatic once you are logged in.
- Auto-relock is disabled on that keychain; otherwise credential fetches would
  start failing about five minutes after login.
- `security find-identity -v` reports nothing for these identities because it
  filters to certificates with a trusted chain, and a self-signed IAM RA CA is
  not in the system trust store. Use `security find-identity` without `-v`.
  `CSSMERR_TP_NOT_TRUSTED` there is expected and harmless - IAM Roles Anywhere
  validates the chain server-side against the trust anchor.

## ACM Private CA Mode

When initialized with `--ca-mode pca-new` or `--ca-mode pca-existing`, host
certificates are issued by an AWS Private CA rather than signed locally.

### How it works

Because the CA's private key lives in AWS (in an HSM), `iam-ra` cannot sign
host certificates itself. It forwards the host's CSR to the PCA:

1. The host generates a key and CSR locally (`iam-ra host request`)
2. `iam-ra host approve` submits the CSR via `acm-pca:IssueCertificate`
3. The signed certificate is retrieved via `acm-pca:GetCertificate`
4. The certificate is returned to the host and installed with
   `iam-ra host install`

The CSR template used is
[`EndEntityClientAuthCertificate/V1`](https://docs.aws.amazon.com/privateca/latest/userguide/UsingTemplates.html#EndEntityClientAuthCertificate-V1),
which produces an end-entity certificate with the Client Authentication EKU
(required by IAM Roles Anywhere) and **passes through the CSR's subject**.

That pass-through is a security-relevant difference between the two CA modes:

| CA mode | Subject handling |
|---|---|
| self-signed | The subject is **rebuilt** from the hostname you approve, so the CSR contributes only a public key and a host cannot obtain a certificate naming another host. |
| ACM Private CA | PCA copies the subject from the CSR, and the template allows no override - so `approve` instead **verifies** the CSR's CN matches the hostname and refuses on mismatch. |

### Prerequisites for pca-existing

If you point `iam-ra init` at an existing PCA (`--pca-arn`), that CA must be in
`ACTIVE` status. A new Private CA starts in `PENDING_CERTIFICATE` and must be
activated with a signed CA certificate before it can issue end-entity certs.

Check status:

```bash
aws acm-pca describe-certificate-authority \
  --certificate-authority-arn arn:aws:acm-pca:...:certificate-authority/... \
  --query 'CertificateAuthority.Status'
```

Expected output: `"ACTIVE"`. If it's anything else (e.g. `PENDING_CERTIFICATE`,
`DISABLED`), `iam-ra host approve` will fail fast with a clear error message
before attempting to issue the certificate.

### Required IAM permissions

In addition to the base permissions, the admin running `iam-ra host approve`
needs:

- `acm-pca:DescribeCertificateAuthority`
- `acm-pca:IssueCertificate`
- `acm-pca:GetCertificate`

Hosts running `iam-ra host request` and `iam-ra host install` need no AWS
permissions at all.

## Module Configuration

### NixOS/Darwin (System Module)

```nix
programs.iamRolesAnywhere = {
  enable = true;
  user = "alice";                          # Required: user to configure

  # One or more identities. Each = one AWS account / trust anchor / cert.
  # Most users have a single identity named `default`. For cross-account
  # setups, see examples/hosts/multi-identity.nix.
  identities.default = {
    # Tagged union: `source` selects which other fields are read.
    certificate = {
      source   = "files";                  # or "macosKeychain"
      certPath = "/path/to/cert.pem";      # required when source = "files"
      keyPath  = "/path/to/key.pem";
      # selector.subject = "CN=host";      # used when source = "macosKeychain"
    };

    trustAnchorArn = "arn:aws:rolesanywhere:...";
    region = "ap-southeast-2";
    sessionDuration = 3600;                # Optional: identity-level default

    profiles = {
      myprofile = {
        profileArn = "arn:aws:rolesanywhere:...";
        roleArn = "arn:aws:iam::...:role/...";
        makeDefault = false;               # Create [default] profile too?
        awsProfileName = "myprofile";      # Must be unique across all identities
        sessionDuration = 900;             # Override identity-level default
        output = "json";                   # json, yaml, text, table
        extraConfig = {                    # Additional AWS config
          cli_pager = "";
        };
      };
    };
  };
};
```

### Home Manager (Direct)

Same options, but without `user`:

```nix
programs.iamRolesAnywhere = {
  enable = true;
  identities.default = {
    certificate = { ... };
    trustAnchorArn = "...";
    region = "...";
    profiles = { ... };
  };
};
```

### Readable `~/.aws/config` (Optional)

By default, each profile's `credential_process` in `~/.aws/config` is a single
long line containing the full `aws_signing_helper credential-process` command
with all certificate paths, ARNs, region and session duration inline - easily
400+ characters per profile, making the config file hard to read or diff.

Set `useCredentialProcessWrapper = true` to have the module generate a
per-profile shell wrapper script at `~/.aws/iam-ra/<awsProfileName>.sh` and
reference it by absolute path from `~/.aws/config` instead:

```nix
programs.iamRolesAnywhere = {
  enable = true;
  useCredentialProcessWrapper = true;  # Defaults to false (inline command)

  identities.default = {
    certificate = { ... };
    trustAnchorArn = "...";
    region = "...";
    profiles.admin = { ... };
  };
};
```

With this enabled, `~/.aws/config` becomes:

```ini
[profile admin]
credential_process=/home/alice/.aws/iam-ra/admin.sh
region=ap-southeast-2
output=json
```

And `~/.aws/iam-ra/admin.sh` (managed declaratively by home-manager - it's a
read-only symlink into `/nix/store` that gets regenerated on every
activation):

```bash
#!/usr/bin/env bash
# Generated by programs.iamRolesAnywhere (Nix module).
# DO NOT EDIT - regenerated by home-manager on every activation.
exec /nix/store/.../aws_signing_helper \
  credential-process \
  --certificate /home/alice/.local/state/iam-ra/keys/default-default/cert.pem \
  --private-key /home/alice/.local/state/iam-ra/keys/default-default/key.pem \
  --trust-anchor-arn arn:aws:rolesanywhere:... \
  --profile-arn arn:aws:rolesanywhere:... \
  --role-arn arn:aws:iam::...:role/admin \
  --region ap-southeast-2
```

Tradeoff: one extra file per profile under `~/.aws/iam-ra/` in exchange for a
readable `~/.aws/config` and a scriptable/debuggable credential-process entry
point.

## Restricting Roles to Specific Hosts

By default, any host whose certificate chains to a scope's trust anchor can
assume any role in that scope. `--allowed-hosts` narrows that:

```bash
iam-ra role create deploy --policy arn:... --allowed-hosts 'ci-*'
iam-ra role create admin  --policy arn:... --allowed-hosts mbp
```

This is enforced in the IAM role's trust policy, against the certificate subject
CN that IAM Roles Anywhere exposes as the session tag
`aws:PrincipalTag/x509Subject/CN`. Wildcards work, since the condition uses
`StringLike`.

The default `*` adds **no condition at all** rather than a wildcard one. That is
deliberate: an IAM condition on an absent principal tag evaluates false, so
emitting a wildcard would couple every role to tag presence and break any
profile with custom attribute mappings.

Two caveats worth understanding:

- This is only a real boundary because keys are host-generated. If a host's key
  could be copied, so could its identity, and a CN condition would gate nothing.
- If you set custom `attributeMappings` on a Roles Anywhere profile and omit the
  CN, the tag is dropped and the condition denies. Leave mappings at their
  defaults unless you have a reason not to.

## Using Other Certificate Sources

The `files` source takes any path, so the module still works with certificates
managed outside `iam-ra` - a corporate PKI, cert-manager, or your own CA.

```nix
# Static files
programs.iamRolesAnywhere.identities.default.certificate = {
  source   = "files";
  certPath = "/etc/ssl/iam-ra/cert.pem";
  keyPath  = "/etc/ssl/iam-ra/key.pem";
};
```

If your key comes from a secrets manager, wire the paths through as before:

```nix
# SOPS
programs.iamRolesAnywhere.identities.default.certificate = {
  source   = "files";
  certPath = config.sops.secrets."iam-ra/cert".path;
  keyPath  = config.sops.secrets."iam-ra/key".path;
};

# agenix
programs.iamRolesAnywhere.identities.default.certificate = {
  source   = "files";
  certPath = config.age.secrets.iam-ra-cert.path;
  keyPath  = config.age.secrets.iam-ra-key.path;
};
```

This is supported, but note that it reintroduces exactly what v3 set out to
remove: a private key that exists somewhere other than the host that uses it.
If the key was generated by `iam-ra host request`, it is already on the host and
encrypting a second copy of it into your repo gains nothing. Prefer a
secrets-manager path only when something else owns the key's lifecycle.

`keyPath` must be a real, re-readable file. The credential helper re-opens the
key on every operation, so a FIFO, process substitution, or `/dev/stdin` fails
after the first read.

## Architecture

```text
AWS Account
├── CloudFormation Stacks
│   ├── iam-ra-{namespace}-init        (S3, KMS, Lambdas)
│   ├── iam-ra-{namespace}-ca-{scope}  (CA + Trust Anchor, per scope)
│   └── iam-ra-{namespace}-role-*      (IAM Roles + Profiles)
├── S3 Bucket
│   ├── {namespace}/state.json
│   └── {namespace}/scopes/{scope}/ca/certificate.pem
└── SSM Parameters
    └── /iam-ra/{namespace}/state-location

  No per-host stack. No host certificate or key in S3.
  No Secrets Manager entries. v3 creates none of these.

Admin workstation
└── ~/.local/share/iam-ra/
    └── {namespace}/scopes/{scope}/ca-private-key.pem  (self-signed CA only)

Host
├── ~/.local/state/iam-ra/keys/{namespace}-{scope}/
│   ├── key.pem            (0600, generated here, never leaves)
│   └── cert.pem           (0644, public)
│      ...or, with --key-store macosKeychain:
├── ~/Library/Keychains/iam-ra.keychain   (key non-extractable)
├── ~/.aws/config          (credential_process for each profile)
└── ~/.aws/iam-ra/         (optional: per-profile wrapper scripts,
                            enabled by useCredentialProcessWrapper)
```

The CA private key on the admin workstation is now the most sensitive material
in the system, since host keys are no longer copied anywhere. See
[SECURITY.md](SECURITY.md).

## Directory Structure

```text
iam-roles-anywhere/
├── flake.nix
├── README.md
├── SECURITY.md              # Threat model
├── VERSION
├── docs/
│   ├── KUBERNETES.md        # K8s integration guide
│   ├── MIGRATION-v3.md      # v2 -> v3 upgrade guide
│   └── cli-design.md        # CLI structure and conventions
├── examples/
│   ├── hosts/               # Nix host configurations
│   └── k8s/                 # Kubernetes manifests
├── nix/
│   ├── package.nix           # CLI package (uv2nix)
│   ├── module.nix            # Module exports
│   ├── module-options.nix    # Option definitions
│   ├── module-aws-profile.nix # Multi-identity AWS CLI config
│   ├── module-validation.nix # ARN + certificate-source validation
│   ├── module-packages.nix   # Package installation
│   ├── lib.nix               # Helper functions
│   └── checks.nix            # Nix tests
├── src/iam_ra_cli/
│   ├── main.py               # CLI entry point
│   ├── commands/             # CLI commands
│   ├── workflows/            # Orchestration logic
│   ├── operations/           # Atomic operations
│   ├── lib/                  # Infrastructure helpers
│   │   ├── crypto.py         # CSR/certificate signing
│   │   └── keystore.py       # files + macosKeychain backends
│   ├── models/               # Data models
│   └── data/cloudformation/  # CFN templates
├── tests/                    # Python tests
└── cloudformation/           # Standalone CFN templates
```

## Troubleshooting

### "Namespace not initialized"

```bash
iam-ra init
```

### "Role not found"

```bash
iam-ra role list
iam-ra role create myrole --policy arn:aws:iam::aws:policy/...
```

### "certificate public key does not match the stored private key"

`iam-ra host install` refused the certificate because it does not belong to the
key this host is holding. Usually one of:

- the certificate is for a different host
- `iam-ra host request` was run again after the certificate was issued, which
  rotated the key and invalidated it - re-run `approve` with the newer CSR
- `--scope` or `--namespace` differs between `request` and `install`, so it is
  looking at a different key

### "Certificate not trusted"

```bash
# Check certificate validity (files key store)
openssl x509 -in ~/.local/state/iam-ra/keys/default-default/cert.pem \
  -noout -dates -subject

# Verify trust anchor matches
aws rolesanywhere get-trust-anchor --trust-anchor-id ...
```

### macOS keychain: no identity found

```bash
# List identities. Do NOT use -v: it filters to system-trusted chains,
# which a self-signed IAM RA CA is not, so it reports nothing.
security find-identity ~/Library/Keychains/iam-ra.keychain

# Confirm the keychain is on the search list and unlocked
security list-keychains -d user
security unlock-keychain ~/Library/Keychains/iam-ra.keychain
```

`CSSMERR_TP_NOT_TRUSTED` in that output is expected - the chain is validated by
IAM Roles Anywhere against the trust anchor, not by macOS.

### "ACM Private CA is in status 'PENDING_CERTIFICATE'"

The PCA you're using must be activated before it can issue host certificates.
A CA in `PENDING_CERTIFICATE` has been created but has no signed CA certificate
installed yet.

```bash
# If you created the CA via iam-ra init --ca-mode pca-new, CloudFormation
# should have activated it. Verify:
aws acm-pca describe-certificate-authority \
  --certificate-authority-arn <arn> \
  --query 'CertificateAuthority.Status'

# If pca-existing: you need to activate it yourself. For a ROOT CA:
aws acm-pca get-certificate-authority-csr \
  --certificate-authority-arn <arn> \
  --output text > ca.csr
# ... sign ca.csr with your root/parent CA, then:
aws acm-pca import-certificate-authority-certificate \
  --certificate-authority-arn <arn> \
  --certificate fileb://ca.crt
```

### Test credentials manually

```bash
# files key store
aws_signing_helper credential-process \
  --certificate ~/.local/state/iam-ra/keys/default-default/cert.pem \
  --private-key ~/.local/state/iam-ra/keys/default-default/key.pem \
  --trust-anchor-arn arn:aws:rolesanywhere:... \
  --profile-arn arn:aws:rolesanywhere:... \
  --role-arn arn:aws:iam::...:role/...

# macosKeychain key store
aws_signing_helper credential-process \
  --cert-selector 'Key=x509Subject,Value=CN=mbp' \
  --trust-anchor-arn arn:aws:rolesanywhere:... \
  --profile-arn arn:aws:rolesanywhere:... \
  --role-arn arn:aws:iam::...:role/...
```

Note that `aws_signing_helper` exits 0 even when a `--cert-selector` matches
nothing, printing `No matching identities`. Read the output, not the exit code.

## Upgrading from v2

See [docs/MIGRATION-v3.md](docs/MIGRATION-v3.md). Summary: your namespace, CA,
trust anchors and roles are untouched; each host is re-enrolled once with
`iam-ra host enroll --overwrite` (or the split flow), its Nix `certificate`
block changes shape, and its SOPS cert/key entries and per-host CloudFormation
stack are deleted. Hosts can be migrated one at a time.

## Security

See [SECURITY.md](SECURITY.md) for the threat model, what v3 changed, and the
known gaps.

## License

MIT
