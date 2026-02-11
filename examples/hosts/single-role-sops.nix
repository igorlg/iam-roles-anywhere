# Single Role with SOPS
#
# Basic configuration for a host with one IAM role using SOPS for secrets.
# This is the most common setup.
#
# Prerequisites:
#   iam-ra init
#   iam-ra role create admin --policy arn:aws:iam::aws:policy/AdministratorAccess
#   iam-ra host onboard myhost --role admin
#
{ config, ... }:
{
  # SOPS secrets configuration
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
    user = "alice"; # The user who will use AWS credentials

    # Certificate paths from SOPS
    certificate = {
      certPath = config.sops.secrets."iam-ra/cert".path;
      keyPath = config.sops.secrets."iam-ra/key".path;
    };

    # AWS configuration - get these from: iam-ra status --json
    trustAnchorArn = "arn:aws:rolesanywhere:ap-southeast-2:123456789012:trust-anchor/abc123";
    region = "ap-southeast-2";

    # Single profile
    profiles = {
      admin = {
        profileArn = "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/admin-profile";
        roleArn = "arn:aws:iam::123456789012:role/iam-ra-admin";
        makeDefault = true; # This profile becomes [default] in ~/.aws/config
      };
    };
  };
}
