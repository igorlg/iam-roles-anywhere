# Single Role with 1Password
#
# The private key stays in 1Password and is fetched with `op read` on
# every credential fetch; it is never written to disk. The certificate
# is not secret and is kept as a regular file next to this config.
#
# Prerequisites:
#   iam-ra init
#   iam-ra role create admin --policy arn:aws:iam::aws:policy/AdministratorAccess
#   iam-ra host onboard myhost --role admin --secrets-backend 1password --op-vault Private
#   op read 'op://Private/iam-ra-myhost-default/certificate' > ./iam-ra/myhost-cert.pem
#
# Evaluated by `nix flake check` (iam-ra-example-single-role-1password).
{ ... }:
{
  programs.iamRolesAnywhere = {
    enable = true;
    user = "alice"; # The user who will use AWS credentials

    # Absolute path: credential_process may run without a login shell PATH.
    opPath = "/opt/homebrew/bin/op";

    identities.default = {
      certificate = {
        certPath = ./iam-ra/myhost-cert.pem;
        keyRef = "op://Private/iam-ra-myhost-default/private_key";
      };

      # AWS configuration - printed by: iam-ra host onboard
      trustAnchorArn = "arn:aws:rolesanywhere:ap-southeast-2:123456789012:trust-anchor/abc123";
      region = "ap-southeast-2";

      profiles.admin = {
        profileArn = "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/a1b2c3d4-0000-0000-0000-000000000001";
        roleArn = "arn:aws:iam::123456789012:role/iam-ra-admin";
        makeDefault = true; # This profile becomes [default] in ~/.aws/config
      };
    };
  };
}
