# Host Examples

This directory contains example Nix configurations for hosts using IAM Roles Anywhere.

## Examples

| Example | Description |
|---------|-------------|
| [`minimal.nix`](minimal.nix) | Minimal configuration (single identity, single role) |
| [`single-role-sops.nix`](single-role-sops.nix) | Single role with SOPS secrets |
| [`single-role-agenix.nix`](single-role-agenix.nix) | Single role with agenix secrets |
| [`multi-role.nix`](multi-role.nix) | Multiple roles, one host, one identity (same AWS account) |
| [`multi-role-sops.nix`](multi-role-sops.nix) | Multi-role with SOPS (scenario 2, v2 SOPS schema) |
| [`multi-identity.nix`](multi-identity.nix) | **Cross-account** - one laptop, two AWS accounts (scenario 3) |
| [`full-options.nix`](full-options.nix) | All available options within a single identity |

## Prerequisites

1. Initialize IAM-RA:

   ```bash
   iam-ra init
   ```

2. Create roles:

   ```bash
   iam-ra role create admin --policy arn:aws:iam::aws:policy/AdministratorAccess
   iam-ra role create readonly --policy arn:aws:iam::aws:policy/ReadOnlyAccess
   ```

3. Onboard the host:

   ```bash
   iam-ra host onboard myhost --role admin
   ```

4. Copy the generated SOPS file to your secrets directory.

## Usage

Add to your flake.nix:

```nix
{
  inputs.iam-roles-anywhere.url = "github:igorlg/iam-roles-anywhere";

  outputs = { self, nixpkgs, iam-roles-anywhere, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      modules = [
        iam-roles-anywhere.nixosModules.default
        ./hosts/myhost.nix
      ];
    };
  };
}
```
