# Minimal Configuration
#
# The bare minimum needed to get IAM Roles Anywhere working.
# Good for testing or simple setups.
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

    profiles.default = {
      profileArn = "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/my-profile";
      roleArn = "arn:aws:iam::123456789012:role/my-role";
      makeDefault = true;
    };
  };
}
