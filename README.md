# IAM Roles Anywhere - Nix Flake

Certificate-based AWS authentication for Nix hosts and Kubernetes using [AWS IAM Roles Anywhere](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.html).

## Overview

This flake provides three components:

### 1. Nix Modules (Runtime - installed on hosts)

Configures hosts to **use** IAM Roles Anywhere for AWS authentication:
- `aws-signing-helper` - credential process for IAM Roles Anywhere
- `~/.aws/config` - configured with `credential_process`
- **Multi-profile support** - one host can assume multiple roles
- Secrets-manager agnostic - works with SOPS, agenix, or any secret source

### 2. `iam-ra` CLI (Admin Tool)

A CLI for **managing** IAM Roles Anywhere infrastructure:
- Initialize AWS infrastructure (CloudFormation stacks)
- Create roles with Roles Anywhere profiles
- Onboard hosts (generate certificates, deploy stacks, create SOPS files)
- **Onboard Kubernetes workloads** (generate cert-manager manifests)

### 3. Kubernetes Integration

Generate manifests for Kubernetes workloads to use IAM Roles Anywhere:
- cert-manager Issuer and Certificate resources
- Sidecar-based credential delivery
- Works with any K8s cluster (on-prem, self-managed, EKS)

```
┌─────────────────────────────────────────────────────────────────┐
│                        ADMIN WORKSTATION                        │
│  ┌───────────────┐                                              │
│  │   iam-ra CLI  │  ← Manages AWS infrastructure                │
│  │               │    - iam-ra init                             │
│  │               │    - iam-ra role create <name>               │
│  │               │    - iam-ra host onboard <hostname>          │
│  │               │    - iam-ra k8s setup <cluster>              │
│  │               │    - iam-ra k8s onboard <workload>           │
│  └───────────────┘                                              │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                      NIX HOSTS                                  │
│  ┌───────────────┐                                              │
│  │  Nix Modules  │  ← Uses IAM Roles Anywhere                   │
│  │               │    - aws-signing-helper                      │
│  │               │    - ~/.aws/config (multi-profile)           │
│  └───────────────┘                                              │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                      KUBERNETES CLUSTERS                        │
│  ┌───────────────┐                                              │
│  │  cert-manager │  ← Issues certificates                       │
│  │  + sidecar    │  ← aws_signing_helper serves credentials     │
│  └───────────────┘                                              │
└─────────────────────────────────────────────────────────────────┘
```

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

### 3. Onboard a Host

```bash
iam-ra host onboard myhost --role admin
```

This creates:
- Host CloudFormation stack with certificate in Secrets Manager
- SOPS-encrypted secrets file: `secrets/hosts/myhost/iam-ra.yaml`

### 4. Configure Host in Nix

```nix
{ config, inputs, ... }:
{
  imports = [ inputs.iam-roles-anywhere.nixosModules.default ];

  # Configure secrets (example with SOPS)
  sops.secrets."iam-ra/cert".sopsFile = ./secrets/hosts/myhost/iam-ra.yaml;
  sops.secrets."iam-ra/key".sopsFile = ./secrets/hosts/myhost/iam-ra.yaml;

  programs.iamRolesAnywhere = {
    enable = true;
    user = "alice";
    
    # Certificate (shared across all profiles)
    certificate = {
      certPath = config.sops.secrets."iam-ra/cert".path;
      keyPath = config.sops.secrets."iam-ra/key".path;
    };
    
    # Shared settings
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
}
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

## CLI Commands

```
iam-ra [OPTIONS] COMMAND

Commands:
  init      Initialize IAM Roles Anywhere infrastructure
  destroy   Tear down all infrastructure for a namespace
  status    Show current status
  role      Manage IAM roles
    create  Create role with Roles Anywhere profile
    delete  Delete role
    list    List all roles
  host      Manage hosts
    onboard   Onboard host (cert + stack + SOPS)
    offboard  Remove host
    list      List all hosts
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

# Onboard hosts
iam-ra host onboard webserver --role admin
iam-ra host onboard ci-runner --role deploy --validity-days 90

# Check status
iam-ra status
iam-ra status --json

# Clean up
iam-ra host offboard webserver
iam-ra role delete deploy
iam-ra destroy --yes
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

## Module Configuration

### NixOS/Darwin (System Module)

```nix
programs.iamRolesAnywhere = {
  enable = true;
  user = "alice";                    # Required: user to configure
  
  certificate = {
    certPath = "/path/to/cert.pem";  # Any secrets manager path
    keyPath = "/path/to/key.pem";
  };
  
  trustAnchorArn = "arn:aws:rolesanywhere:...";
  region = "ap-southeast-2";
  sessionDuration = 3600;            # Optional: default session duration
  
  profiles = {
    myprofile = {
      profileArn = "arn:aws:rolesanywhere:...";
      roleArn = "arn:aws:iam::...:role/...";
      makeDefault = false;           # Create [default] profile too?
      awsProfileName = "myprofile";  # Override AWS profile name
      sessionDuration = 900;         # Override per-profile
      output = "json";               # json, yaml, text, table
      extraConfig = {                # Additional AWS config
        cli_pager = "";
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
  certificate = { ... };
  trustAnchorArn = "...";
  region = "...";
  profiles = { ... };
};
```

## Secrets Manager Integration

The module is **secrets-manager agnostic**. Just provide paths to certificate files.

### With SOPS

```nix
sops.secrets."iam-ra/cert" = {
  sopsFile = ./secrets/hosts/myhost/iam-ra.yaml;
  key = "certificate";
};
sops.secrets."iam-ra/key" = {
  sopsFile = ./secrets/hosts/myhost/iam-ra.yaml;
  key = "private_key";
};

programs.iamRolesAnywhere.certificate = {
  certPath = config.sops.secrets."iam-ra/cert".path;
  keyPath = config.sops.secrets."iam-ra/key".path;
};
```

### With agenix

```nix
age.secrets.iam-ra-cert.file = ./secrets/iam-ra-cert.age;
age.secrets.iam-ra-key.file = ./secrets/iam-ra-key.age;

programs.iamRolesAnywhere.certificate = {
  certPath = config.age.secrets.iam-ra-cert.path;
  keyPath = config.age.secrets.iam-ra-key.path;
};
```

### With Static Files

```nix
programs.iamRolesAnywhere.certificate = {
  certPath = "/etc/ssl/iam-ra/cert.pem";
  keyPath = "/etc/ssl/iam-ra/key.pem";
};
```

## Architecture

```
AWS Account
├── CloudFormation Stacks
│   ├── iam-ra-{namespace}-init     (S3, KMS, Lambdas)
│   ├── iam-ra-{namespace}-rootca   (Trust Anchor)
│   ├── iam-ra-{namespace}-role-*   (IAM Roles + Profiles)
│   └── iam-ra-{namespace}-host-*   (Host certificates)
├── S3 Bucket
│   ├── {namespace}/state.json
│   ├── {namespace}/ca/certificate.pem
│   └── {namespace}/hosts/{hostname}/*
├── SSM Parameters
│   └── /iam-ra/{namespace}/state-location
└── Secrets Manager
    └── /iam-ra/{namespace}/hosts/{hostname}/*

Local
├── ~/.local/share/iam-ra/
│   └── {namespace}/ca-private-key.pem  (self-signed CA only)
└── secrets/hosts/{hostname}/iam-ra.yaml (SOPS-encrypted)

Host
├── /run/secrets/iam-ra/*  (deployed by secrets manager)
└── ~/.aws/config          (credential_process for each profile)
```

## Directory Structure

```
iam-roles-anywhere/
├── flake.nix
├── README.md
├── VERSION
├── docs/
│   └── KUBERNETES.md        # K8s integration guide
├── examples/
│   ├── hosts/               # Nix host configurations
│   └── k8s/                 # Kubernetes manifests
├── nix/
│   ├── package.nix           # CLI package (uv2nix)
│   ├── module.nix            # Module exports
│   ├── module-options.nix    # Option definitions
│   ├── module-aws-profile.nix # Multi-profile AWS config
│   ├── module-validation.nix # ARN validation
│   ├── module-packages.nix   # Package installation
│   ├── lib.nix               # Helper functions
│   └── checks.nix            # Nix tests
├── src/iam_ra_cli/
│   ├── main.py               # CLI entry point
│   ├── commands/             # CLI commands
│   ├── workflows/            # Orchestration logic
│   ├── operations/           # Atomic operations
│   ├── lib/                  # Infrastructure helpers
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

### "Certificate not trusted"

```bash
# Check certificate validity
openssl x509 -in /run/secrets/iam-ra/cert -noout -dates -subject

# Verify trust anchor matches
aws rolesanywhere get-trust-anchor --trust-anchor-id ...
```

### Test credentials manually

```bash
aws_signing_helper credential-process \
  --certificate /run/secrets/iam-ra/cert \
  --private-key /run/secrets/iam-ra/key \
  --trust-anchor-arn arn:aws:rolesanywhere:... \
  --profile-arn arn:aws:rolesanywhere:... \
  --role-arn arn:aws:iam::...:role/...
```

## License

MIT
