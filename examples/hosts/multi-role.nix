# Multi-Role Configuration
#
# A single host that can assume multiple IAM roles.
# Use case: A workstation that needs both admin and read-only access.
#
# Prerequisites:
#   iam-ra init
#   iam-ra role create admin --policy arn:aws:iam::aws:policy/AdministratorAccess
#   iam-ra role create readonly --policy arn:aws:iam::aws:policy/ReadOnlyAccess
#   iam-ra role create deploy --policy arn:aws:iam::123456789012:policy/DeployPolicy
#   iam-ra host onboard workstation --role admin
#
{ config, ... }:
{
  sops.secrets."iam-ra/cert".sopsFile = ./secrets/iam-ra.yaml;
  sops.secrets."iam-ra/key".sopsFile = ./secrets/iam-ra.yaml;

  programs.iamRolesAnywhere = {
    enable = true;
    user = "alice";

    certificate = {
      certPath = config.sops.secrets."iam-ra/cert".path;
      keyPath = config.sops.secrets."iam-ra/key".path;
    };

    trustAnchorArn = "arn:aws:rolesanywhere:ap-southeast-2:123456789012:trust-anchor/abc123";
    region = "ap-southeast-2";

    # Global session duration (can be overridden per-profile)
    sessionDuration = 3600; # 1 hour

    # Multiple profiles - same certificate, different roles
    profiles = {
      # Admin access - use sparingly
      admin = {
        profileArn = "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/admin-profile";
        roleArn = "arn:aws:iam::123456789012:role/iam-ra-admin";
        # Don't make admin the default - be explicit
        makeDefault = false;
        sessionDuration = 900; # 15 minutes - shorter for admin
      };

      # Read-only access - safe for day-to-day use
      readonly = {
        profileArn = "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/readonly-profile";
        roleArn = "arn:aws:iam::123456789012:role/iam-ra-readonly";
        makeDefault = true; # Safe default
      };

      # Deploy access - for CI/CD operations
      deploy = {
        profileArn = "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/deploy-profile";
        roleArn = "arn:aws:iam::123456789012:role/iam-ra-deploy";
        sessionDuration = 7200; # 2 hours for long deployments
      };
    };
  };
}

# Usage:
#   aws sts get-caller-identity              # Uses readonly (default)
#   aws sts get-caller-identity --profile readonly
#   aws sts get-caller-identity --profile admin
#   aws sts get-caller-identity --profile deploy
