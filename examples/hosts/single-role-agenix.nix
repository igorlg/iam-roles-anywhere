# Single Role with agenix
#
# Configuration for a host using agenix for secret management.
#
# Prerequisites:
#   iam-ra init
#   iam-ra role create admin --policy arn:aws:iam::aws:policy/AdministratorAccess
#   iam-ra host onboard myhost --role admin --no-sops
#   # Then manually create age-encrypted secrets
#
{ config, ... }:
{
  # agenix secrets configuration
  age.secrets.iam-ra-cert = {
    file = ./secrets/iam-ra-cert.age;
    owner = "alice";
  };
  age.secrets.iam-ra-key = {
    file = ./secrets/iam-ra-key.age;
    owner = "alice";
  };

  programs.iamRolesAnywhere = {
    enable = true;
    user = "alice";

    # Certificate paths from agenix
    certificate = {
      certPath = config.age.secrets.iam-ra-cert.path;
      keyPath = config.age.secrets.iam-ra-key.path;
    };

    # AWS configuration
    trustAnchorArn = "arn:aws:rolesanywhere:ap-southeast-2:123456789012:trust-anchor/abc123";
    region = "ap-southeast-2";

    profiles = {
      admin = {
        profileArn = "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/admin-profile";
        roleArn = "arn:aws:iam::123456789012:role/iam-ra-admin";
        makeDefault = true;
      };
    };
  };
}
