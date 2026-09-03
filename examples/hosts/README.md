# Host Examples

This directory contains example Nix configurations for hosts using IAM Roles Anywhere.

## Examples

| Example | Description |
|---------|-------------|
| [`minimal.nix`](minimal.nix) | Minimal configuration (single identity, single role) |
| [`keychain.nix`](keychain.nix) | macOS Keychain key store - key is non-extractable (Darwin only) |
| [`multi-role.nix`](multi-role.nix) | Multiple roles, one host, one identity (same AWS account) |
| [`multi-identity.nix`](multi-identity.nix) | **Cross-account** - one laptop, two AWS accounts |
| [`full-options.nix`](full-options.nix) | All available options within a single identity |
| [`external-secrets.nix`](external-secrets.nix) | Certificates from SOPS, agenix, or an external PKI |

## Prerequisites

1. Initialize IAM-RA (once per namespace, on a machine with AWS access):

   ```bash
   iam-ra init
   ```

2. Create roles:

   ```bash
   iam-ra role create admin --policy arn:aws:iam::aws:policy/AdministratorAccess
   iam-ra role create readonly --policy arn:aws:iam::aws:policy/ReadOnlyAccess
   ```

3. Enrol the host. If the host has AWS access:

   ```bash
   iam-ra host enroll myhost --role admin
   ```

   If it does not, run three commands across two machines:

   ```bash
   iam-ra host request myhost --out myhost.csr                    # on the host
   iam-ra host approve myhost --role admin --csr myhost.csr \
     --out myhost.pem                                             # at the CA
   iam-ra host install myhost --certificate myhost.pem            # on the host
   ```

4. Paste the printed `programs.iamRolesAnywhere` block into your host's
   configuration and rebuild.

There is no step to copy a private key or a SOPS file anywhere. The key is
generated on the host and never leaves it; the certificate is public.

## Choosing a certificate source

`certificate.source` is a tagged union - it selects which of the other
`certificate` fields are read:

| `source` | Fields used | Key readable by |
|---|---|---|
| `"files"` (default) | `certPath`, `keyPath` | any process running as the owning user, and root |
| `"macosKeychain"` | `selector.{subject,issuer,serial}` | nothing - marked non-extractable |

It is a union rather than a set of optional flags because `aws_signing_helper`
treats `--cert-selector` as mutually exclusive with `--certificate` and
`--private-key`, so the argument sets are genuinely disjoint.

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
