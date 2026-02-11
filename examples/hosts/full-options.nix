# Full Options Example
#
# Demonstrates all available configuration options.
# Use this as a reference for what's possible.
#
{ config, ... }:
{
  sops.secrets."iam-ra/cert".sopsFile = ./secrets/iam-ra.yaml;
  sops.secrets."iam-ra/key".sopsFile = ./secrets/iam-ra.yaml;

  programs.iamRolesAnywhere = {
    enable = true;
    user = "alice";

    # Certificate configuration
    certificate = {
      certPath = config.sops.secrets."iam-ra/cert".path;
      keyPath = config.sops.secrets."iam-ra/key".path;
    };

    # AWS configuration
    trustAnchorArn = "arn:aws:rolesanywhere:ap-southeast-2:123456789012:trust-anchor/abc123";
    region = "ap-southeast-2";

    # Global session duration (seconds)
    # This is the default for all profiles unless overridden
    sessionDuration = 3600; # 1 hour

    # Profile definitions
    profiles = {
      # Example 1: Simple profile with custom AWS profile name
      production = {
        profileArn = "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/prod-profile";
        roleArn = "arn:aws:iam::123456789012:role/iam-ra-production";

        # Use a different name in ~/.aws/config
        awsProfileName = "prod";

        # Make this the [default] profile
        makeDefault = false;
      };

      # Example 2: Profile with all options
      admin = {
        profileArn = "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/admin-profile";
        roleArn = "arn:aws:iam::123456789012:role/iam-ra-admin";

        # AWS profile name (defaults to the attribute name "admin")
        awsProfileName = "admin";

        # Whether to also create [default] profile with same settings
        makeDefault = true;

        # Override session duration for this profile
        sessionDuration = 900; # 15 minutes

        # AWS CLI output format
        output = "json"; # or "yaml", "text", "table"

        # Additional AWS config options
        extraConfig = {
          cli_pager = ""; # Disable pager
          retry_mode = "standard";
          max_attempts = "3";
        };
      };

      # Example 3: Read-only profile with short sessions
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
