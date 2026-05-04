# Full Options Example
#
# Demonstrates all available configuration options for a single
# identity. For multi-identity (cross-account) setups see
# ./multi-identity.nix.
#
# The module is organised around identities: each identity owns a
# cert, trust anchor, region, and set of profiles. Profiles within
# an identity share the cert.
#
{ config, ... }:
{
  sops.secrets."iam-ra/cert".sopsFile = ./secrets/iam-ra-default.yaml;
  sops.secrets."iam-ra/key".sopsFile = ./secrets/iam-ra-default.yaml;

  programs.iamRolesAnywhere = {
    enable = true;
    user = "alice";

    identities.default = {
      # Certificate configuration (shared across all profiles in this
      # identity).
      certificate = {
        certPath = config.sops.secrets."iam-ra/cert".path;
        keyPath = config.sops.secrets."iam-ra/key".path;
      };

      # AWS configuration for this identity
      trustAnchorArn = "arn:aws:rolesanywhere:ap-southeast-2:123456789012:trust-anchor/abc123";
      region = "ap-southeast-2";

      # Identity-level default session duration (seconds). Individual
      # profiles can override this via their own sessionDuration.
      sessionDuration = 3600; # 1 hour

      # Profile definitions - one per IAM role this identity can assume
      profiles = {
        # Example 1: Simple profile with custom AWS CLI profile name
        production = {
          profileArn = "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/prod-profile";
          roleArn = "arn:aws:iam::123456789012:role/iam-ra-production";

          # Use a different name in ~/.aws/config
          awsProfileName = "prod";

          # Not the default - "prod" never should be (user must opt in)
          makeDefault = false;
        };

        # Example 2: Profile with all options set explicitly
        admin = {
          profileArn = "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/admin-profile";
          roleArn = "arn:aws:iam::123456789012:role/iam-ra-admin";

          # AWS profile name (defaults to the attribute name "admin").
          # Must be unique across ALL identities in the full
          # programs.iamRolesAnywhere config.
          awsProfileName = "admin";

          # At most ONE profile across ALL identities may set this.
          makeDefault = true;

          # Override the identity-level session duration
          sessionDuration = 900; # 15 minutes

          # AWS CLI output format
          output = "json"; # or "yaml", "text", "table"

          # Additional AWS config options written verbatim into
          # [profile admin] in ~/.aws/config
          extraConfig = {
            cli_pager = ""; # Disable pager
            retry_mode = "standard";
            max_attempts = "3";
          };
        };

        # Example 3: Read-only profile using identity's default duration
        readonly = {
          profileArn = "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/readonly-profile";
          roleArn = "arn:aws:iam::123456789012:role/iam-ra-readonly";
          output = "table"; # Nice for interactive use
        };

        # Example 4: Deploy profile for CI/CD
        deploy = {
          profileArn = "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/deploy-profile";
          roleArn = "arn:aws:iam::123456789012:role/iam-ra-deploy";
          sessionDuration = 7200; # 2 hours for long deployments
          output = "json";
          extraConfig = {
            cli_pager = "";
          };
        };
      };
    };
  };
}

# Generated ~/.aws/config will look like:
#
# [default]
# credential_process = /nix/store/.../aws_signing_helper credential-process ...
# region = ap-southeast-2
# output = json
# cli_pager =
# retry_mode = standard
# max_attempts = 3
#
# [profile admin]
# credential_process = /nix/store/.../aws_signing_helper credential-process ...
# region = ap-southeast-2
# output = json
# cli_pager =
# retry_mode = standard
# max_attempts = 3
#
# [profile prod]
# credential_process = /nix/store/.../aws_signing_helper credential-process ...
# region = ap-southeast-2
# output = json
#
# [profile readonly]
# credential_process = /nix/store/.../aws_signing_helper credential-process ...
# region = ap-southeast-2
# output = table
#
# [profile deploy]
# credential_process = /nix/store/.../aws_signing_helper credential-process ...
# region = ap-southeast-2
# output = json
# cli_pager =
