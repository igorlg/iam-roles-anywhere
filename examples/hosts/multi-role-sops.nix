# Multi-Role with SOPS (v2 SOPS schema)
#
# Scenario 2 of the multi-identity plan: one host cert authenticates against
# multiple IAM roles, all under the same AWS Roles Anywhere trust anchor.
#
# Pair this example with the scenario-2 CLI workflow:
#
#   iam-ra init
#   iam-ra role create admin    --policy arn:aws:iam::aws:policy/AdministratorAccess
#   iam-ra role create readonly --policy arn:aws:iam::aws:policy/ReadOnlyAccess
#   iam-ra role create deploy   --policy arn:aws:iam::123:policy/DeployPolicy
#
#   # Initial onboard - one host, multiple roles under one cert:
#   iam-ra host onboard workstation --role admin --role readonly
#
#   # Later: attach an additional role without reissuing the cert
#   iam-ra host add-role workstation deploy
#
#   # Renew the cert while keeping all roles:
#   iam-ra host rotate-cert workstation
#
# The CLI writes a v2 SOPS file at secrets/hosts/workstation/iam-ra.yaml with:
#   - certificate / private_key (top-level - same as v1, SOPS wiring below
#     continues to work)
#   - account_id, trust_anchor_arn, region (top-level metadata)
#   - profiles: { admin: {...}, readonly: {...}, deploy: {...} } (nested map)
#
# The ARNs below are not secrets - they can live in plain Nix alongside the
# encrypted cert/key. `iam-ra host onboard --json` outputs them in a
# machine-readable shape for pasting.
#
{ config, ... }:
{
  # Same SOPS file, same wiring as single-role-sops.nix. v2 puts certificate
  # and private_key at the top of the YAML just like v1 did.
  sops.secrets."iam-ra/cert" = {
    sopsFile = ./secrets/iam-ra.yaml;
    key = "certificate";
  };
  sops.secrets."iam-ra/key" = {
    sopsFile = ./secrets/iam-ra.yaml;
    key = "private_key";
  };

  programs.iamRolesAnywhere = {
    enable = true;
    user = "alice";

    # One certificate - shared across all profiles below
    certificate = {
      certPath = config.sops.secrets."iam-ra/cert".path;
      keyPath = config.sops.secrets."iam-ra/key".path;
    };

    trustAnchorArn = "arn:aws:rolesanywhere:ap-southeast-2:123456789012:trust-anchor/abc123";
    region = "ap-southeast-2";
    sessionDuration = 3600;

    # Multiple profiles - one per role. Add / remove entries here to match
    # `iam-ra host add-role` / `remove-role` invocations.
    profiles = {
      admin = {
        profileArn = "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/admin-profile";
        roleArn = "arn:aws:iam::123456789012:role/iam-ra-admin";
        sessionDuration = 900; # shorter for admin
      };
      readonly = {
        profileArn = "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/readonly-profile";
        roleArn = "arn:aws:iam::123456789012:role/iam-ra-readonly";
        makeDefault = true; # safest default
      };
      deploy = {
        profileArn = "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/deploy-profile";
        roleArn = "arn:aws:iam::123456789012:role/iam-ra-deploy";
        sessionDuration = 7200;
      };
    };
  };
}

# Usage:
#   aws sts get-caller-identity              # uses readonly (default)
#   aws sts get-caller-identity --profile admin
#   aws sts get-caller-identity --profile deploy
