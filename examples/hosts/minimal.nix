# Minimal Configuration
#
# The bare minimum needed to get IAM Roles Anywhere working.
# Good for testing or simple setups.
#
# Single identity = single AWS account. For cross-account setups see
# ./multi-identity.nix.
#
# Prerequisites:
#   iam-ra init
#   iam-ra role create admin --policy arn:aws:iam::aws:policy/AdministratorAccess
#   iam-ra host enroll myhost --role admin
#
# `host enroll` generates the private key on this machine and prints the
# block below, filled in. No secrets manager is involved: the key never
# leaves the host, and the certificate is public.
#
{ ... }:
{
  programs.iamRolesAnywhere = {
    enable = true;
    user = "alice";

    identities.default = {
      certificate = {
        source = "files";
        certPath = "/home/alice/.local/state/iam-ra/keys/default-default/cert.pem";
        keyPath = "/home/alice/.local/state/iam-ra/keys/default-default/key.pem";
      };

      trustAnchorArn = "arn:aws:rolesanywhere:ap-southeast-2:123456789012:trust-anchor/abc123";
      region = "ap-southeast-2";

      profiles.default = {
        profileArn = "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/my-profile";
        roleArn = "arn:aws:iam::123456789012:role/my-role";
        makeDefault = true;
      };
    };
  };
}
