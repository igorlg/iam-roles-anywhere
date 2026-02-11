# IAM Roles Anywhere - Nix Flake

Certificate-based AWS authentication for Nix hosts using [AWS IAM Roles Anywhere](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.html).

## Overview

This flake provides two distinct components:

### 1. Nix Modules (Runtime - installed on hosts)

Configures hosts to **use** IAM Roles Anywhere for AWS authentication:
- `aws-signing-helper` - credential process for IAM Roles Anywhere
- `~/.aws/config` - configured with `credential_process`
- Secrets-manager agnostic - works with SOPS, agenix, or any secret source

### 2. `iam-ra-cli` (Admin Tool - NOT installed on hosts)

A self-contained CLI for **managing** IAM Roles Anywhere infrastructure:
- Initializes AWS infrastructure (CloudFormation stacks)
- Onboards new hosts (deploys stack + fetches secrets)
- Bundles SAM CLI internally - no external dependencies

```
┌─────────────────────────────────────────────────────────────────┐
│                        ADMIN WORKSTATION                        │
│  ┌───────────────┐                                              │
│  │  iam-ra-cli   │  ← Manages AWS infrastructure                │
│  │               │    - iam-ra init                             │
│  │  (installed   │    - iam-ra onboard <host>                   │
│  │   selectively)│                                              │
│  └───────────────┘                                              │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                      ALL IAM-RA HOSTS                           │
│  ┌───────────────┐                                              │
│  │  Nix Modules  │  ← Uses IAM Roles Anywhere                   │
│  │               │    - aws-signing-helper                      │
│  │  (installed   │    - ~/.aws/config                           │
│  │   by default) │    - awscli2, openssl                        │
│  └───────────────┘                                              │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

### 1. Initialize Infrastructure (once per AWS account)

```bash
# From repo root (admin workstation)
nix run .#iam-ra-cli -- init

# Or if iam-ra-cli is installed:
iam-ra init
```

### 2. Onboard a Host

```bash
# Deploys host stack + creates SOPS secrets file
iam-ra onboard myhost
```

### 3. Configure Host in Nix

The module is **secrets-manager agnostic** - it only needs paths to certificate files. Here are examples with different secret managers:

#### With SOPS

```nix
{ config, ... }:
{
  sops.secrets."iam-ra/cert" = {
    sopsFile = ../../../secrets/hosts/myhost/iam-ra.yaml;
    key = "certificate";
  };
  sops.secrets."iam-ra/key" = {
    sopsFile = ../../../secrets/hosts/myhost/iam-ra.yaml;
    key = "private_key";
  };

  programs.iamRolesAnywhere = {
    enable = true;
    user = config.system.primaryUser;  # For NixOS/Darwin system modules
    certificate = {
      certPath = config.sops.secrets."iam-ra/cert".path;
      keyPath = config.sops.secrets."iam-ra/key".path;
    };
    aws = {
      region = "ap-southeast-2";
      trustAnchorArn = "arn:aws:rolesanywhere:...";
      profileArn = "arn:aws:rolesanywhere:...";
      roleArn = "arn:aws:iam::...:role/...";
    };
  };
}
```

#### With agenix

```nix
{ config, ... }:
{
  age.secrets.iam-ra-cert.file = ../../../secrets/iam-ra-cert.age;
  age.secrets.iam-ra-key.file = ../../../secrets/iam-ra-key.age;

  programs.iamRolesAnywhere = {
    enable = true;
    user = "alice";
    certificate = {
      certPath = config.age.secrets.iam-ra-cert.path;
      keyPath = config.age.secrets.iam-ra-key.path;
    };
    aws = {
      region = "ap-southeast-2";
      trustAnchorArn = "arn:aws:rolesanywhere:...";
      profileArn = "arn:aws:rolesanywhere:...";
      roleArn = "arn:aws:iam::...:role/...";
    };
  };
}
```

#### With Static Files

```nix
{
  programs.iamRolesAnywhere = {
    enable = true;
    user = "alice";
    certificate = {
      certPath = "/etc/ssl/iam-ra/cert.pem";
      keyPath = "/etc/ssl/iam-ra/key.pem";
    };
    aws = {
      region = "ap-southeast-2";
      trustAnchorArn = "arn:aws:rolesanywhere:...";
      profileArn = "arn:aws:rolesanywhere:...";
      roleArn = "arn:aws:iam::...:role/...";
    };
  };
}
```

### 4. Deploy and Test

```bash
# Deploy your configuration
nixos-rebuild switch  # or darwin-rebuild switch

# Test the credentials
aws sts get-caller-identity --profile iam-ra
```

## Installing `iam-ra-cli`

The CLI is **not** installed on hosts by default. Install it only on admin workstations:

### Option 1: Run directly (no installation)

```bash
nix run .#iam-ra-cli -- init
nix run .#iam-ra-cli -- onboard myhost
```

### Option 2: In dev shell

```bash
nix develop
iam-ra init
iam-ra onboard myhost
```

### Option 3: Install on specific host

```nix
# In host's home-manager config
{ inputs, ... }:
{
  home.packages = [
    inputs.iam-roles-anywhere.packages.${system}.iam-ra-cli
  ];
}
```

## CLI Commands

### `iam-ra init`

Initialize IAM Roles Anywhere infrastructure (once per AWS account):

```bash
iam-ra init                              # Default: self-managed CA
iam-ra init --ca-mode pca-create         # Create new AWS Private CA
iam-ra init --ca-mode pca-existing --pca-arn arn:aws:acm-pca:...
iam-ra init --dry-run                    # Preview changes
```

Deploys:
- `iam-ra-rootca` - Root CA stack (self-managed or ACM PCA)
- `iam-ra-account` - Trust Anchor + Certificate Issuer Lambda

### `iam-ra onboard <hostname>`

Onboard a host (deploys stack + creates SOPS secrets):

```bash
iam-ra onboard myhost                    # Full onboarding
iam-ra onboard myhost --dry-run          # Preview changes
iam-ra onboard myhost --skip-deploy      # Only fetch secrets (stack exists)
iam-ra onboard myhost --force            # Overwrite existing secrets file
iam-ra onboard myhost --policy-arns arn:aws:iam::aws:policy/ReadOnlyAccess
```

Performs:
1. Deploys `iam-ra-host-<hostname>` CloudFormation stack
2. Retrieves certificate and private key from Secrets Manager
3. Creates SOPS-encrypted `secrets/hosts/<hostname>/iam-ra.yaml`

## Modules

| Module | Platform | Description |
|--------|----------|-------------|
| `homeModules.default` | Any | Direct home-manager use, configures ~/.aws/config |
| `nixosModules.default` | NixOS | System-level, adds `user` option, wires home-manager |
| `darwinModules.default` | macOS | System-level, adds `user` option, wires home-manager |

## Configuration Options

### Certificate Paths

| Option | Description |
|--------|-------------|
| `certificate.certPath` | Path to X.509 certificate (any secrets manager path) |
| `certificate.keyPath` | Path to private key (any secrets manager path) |

### AWS Configuration

| Option | Description | Required |
|--------|-------------|----------|
| `aws.region` | AWS region | Yes |
| `aws.trustAnchorArn` | Trust anchor ARN | Yes |
| `aws.profileArn` | Profile ARN | Yes |
| `aws.roleArn` | IAM role ARN | Yes |
| `aws.sessionDuration` | Session duration (seconds) | No (3600) |

### AWS Profile

| Option | Description | Default |
|--------|-------------|---------|
| `awsProfile.name` | AWS CLI profile name | `iam-ra` |
| `awsProfile.makeDefault` | Also set as default profile | `false` |
| `awsProfile.output` | Default output format | `json` |
| `awsProfile.extraConfig` | Additional settings | `{}` |

### System Module Only

| Option | Description |
|--------|-------------|
| `user` | Username to configure IAM Roles Anywhere for |

## Architecture

```
AWS Account
├── CloudFormation Stacks
│   ├── iam-ra-rootca (CA setup)
│   ├── iam-ra-account (Trust Anchor + Lambda)
│   └── iam-ra-host-<hostname> (per host)
├── Secrets Manager
│   └── /iam-ra-hosts/<hostname>/{certificate,private-key}
└── SSM Parameters
    └── /iam-ra/{trust-anchor-arn,certificate-issuer-arn,...}

Git Repository
└── secrets/hosts/<hostname>/iam-ra.yaml (SOPS-encrypted backup)

Nix Host
├── /run/secrets/iam-ra/{cert,key} (deployed by secrets manager)
└── ~/.aws/config (credential_process → aws_signing_helper)
```

## Directory Structure

```
iam-roles-anywhere/
├── flake.nix
├── README.md
├── lib/
│   ├── default.nix              # ARN validation, command builders
│   └── _unused.nix              # Archived functions for future use
├── modules/
│   ├── default.nix              # Module exports (home, nixos, darwin)
│   ├── options.nix              # Option definitions (API surface)
│   ├── packages.nix             # Package installation
│   ├── aws-profile.nix          # AWS CLI profile configuration
│   └── validation.nix           # ARN assertions and warnings
└── iam-ra-cli/
    ├── pyproject.toml           # Python package definition
    ├── iam_ra_cli/
    │   ├── main.py              # CLI entry point
    │   ├── commands/
    │   │   ├── init.py          # iam-ra init
    │   │   └── onboard.py       # iam-ra onboard
    │   ├── lib/
    │   │   ├── aws.py           # Secrets Manager helpers
    │   │   ├── cfn.py           # CloudFormation helpers
    │   │   ├── sops.py          # SOPS helpers
    │   │   └── templates.py     # SAM runner
    │   └── data/
    │       └── cloudformation/  # Bundled SAM templates
    │           ├── account-rootca-stack.yaml
    │           ├── account-iamra-stack.yaml
    │           ├── host-stack.yaml
    │           ├── ca_generator/
    │           └── certificate_issuer/
    └── tests/
```

## Troubleshooting

### "No certificate found"
- Ensure secrets are configured in host config
- Check paths match: `certificate.certPath` ↔ your secrets manager path

### "Certificate not trusted"
- Verify certificate signed by CA in trust anchor
- Check validity: `openssl x509 -in cert.pem -noout -dates`

### "Access denied assuming role"
- Check IAM role trust policy conditions
- Verify certificate CN matches hostname

### Test manually
```bash
aws_signing_helper credential-process \
  --certificate /run/secrets/iam-ra/cert \
  --private-key /run/secrets/iam-ra/key \
  --trust-anchor-arn arn:aws:rolesanywhere:... \
  --profile-arn arn:aws:rolesanywhere:... \
  --role-arn arn:aws:iam::...:role/...
```

## References

- [AWS IAM Roles Anywhere](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.html)
- [aws_signing_helper](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/credential-helper.html)

