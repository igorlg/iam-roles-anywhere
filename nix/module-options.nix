# IAM Roles Anywhere - Option Definitions
#
# Pure option definitions for the IAM Roles Anywhere module.
# This file defines the API surface - no implementation logic.
#
# Supports multiple profiles per host, each assuming a different role.
# The certificate is shared across all profiles (one identity per host).
{ lib }:

let
  # Profile submodule - defines options for each named profile
  profileSubmodule =
    { name, ... }:
    {
      options = {
        profileArn = lib.mkOption {
          type = lib.types.str;
          description = "ARN of the IAM Roles Anywhere profile";
          example = "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/def456";
        };

        roleArn = lib.mkOption {
          type = lib.types.str;
          description = "ARN of the IAM role to assume";
          example = "arn:aws:iam::123456789012:role/my-role";
        };

        awsProfileName = lib.mkOption {
          type = lib.types.str;
          default = name;
          description = ''
            Name of the AWS CLI profile to create.
            Defaults to the attribute name in the profiles set.
          '';
          example = "my-profile";
        };

        makeDefault = lib.mkOption {
          type = lib.types.bool;
          default = false;
          description = ''
            If true, also configure the [default] profile with these settings.
            Only one profile should have this set to true.
          '';
        };

        sessionDuration = lib.mkOption {
          type = lib.types.nullOr lib.types.int;
          default = null;
          description = "Session duration in seconds (default: 3600). Overrides global setting.";
          example = 3600;
        };

        output = lib.mkOption {
          type = lib.types.enum [
            "json"
            "yaml"
            "text"
            "table"
          ];
          default = "json";
          description = "Default output format for AWS CLI";
        };

        extraConfig = lib.mkOption {
          type = lib.types.attrsOf lib.types.str;
          default = { };
          description = "Additional configuration options for the AWS CLI profile";
          example = {
            cli_pager = "";
            retry_mode = "standard";
          };
        };
      };
    };
in
{
  enable = lib.mkEnableOption "IAM Roles Anywhere authentication";

  # ===================
  # CERTIFICATE PATHS
  # ===================
  # The certificate identifies the host. It's shared across all profiles.
  # This module is secrets-manager agnostic - paths can come from:
  #   - SOPS: config.sops.secrets."iam-ra/cert".path
  #   - agenix: config.age.secrets.iam-ra-cert.path
  #   - Static files: "/etc/ssl/iam-ra/cert.pem"

  certificate = {
    certPath = lib.mkOption {
      type = lib.types.either lib.types.path lib.types.str;
      description = ''
        Path to the X.509 certificate file (PEM format).
        This certificate identifies the host and is shared across all profiles.
      '';
      example = "/run/secrets/iam-ra/cert.pem";
    };

    keyPath = lib.mkOption {
      type = lib.types.either lib.types.path lib.types.str;
      description = ''
        Path to the private key file (PEM format).
        This key corresponds to the certificate and is shared across all profiles.
      '';
      example = "/run/secrets/iam-ra/key.pem";
    };
  };

  # ===================
  # SHARED AWS CONFIG
  # ===================
  # These settings are shared across all profiles.

  trustAnchorArn = lib.mkOption {
    type = lib.types.str;
    description = "ARN of the IAM Roles Anywhere trust anchor (shared across all profiles)";
    example = "arn:aws:rolesanywhere:ap-southeast-2:123456789012:trust-anchor/abc123";
  };

  region = lib.mkOption {
    type = lib.types.str;
    description = "AWS region for API calls (shared across all profiles)";
    example = "ap-southeast-2";
  };

  sessionDuration = lib.mkOption {
    type = lib.types.nullOr lib.types.int;
    default = null;
    description = "Default session duration in seconds. Can be overridden per-profile.";
    example = 3600;
  };

  # ===================
  # PROFILES
  # ===================
  # Each profile can assume a different IAM role.
  # The profile name becomes the AWS CLI profile name by default.

  profiles = lib.mkOption {
    type = lib.types.attrsOf (lib.types.submodule profileSubmodule);
    default = { };
    description = ''
      Named profiles for IAM Roles Anywhere authentication.
      Each profile can assume a different IAM role using the same host certificate.
      The attribute name is used as the AWS CLI profile name by default.

      All profiles share the certificate, private key, and trust anchor
      above - they must therefore all belong to the same scope (same trust
      anchor, same AWS account). For cross-scope / cross-account identities
      (scenario 3 in the multi-identity plan), multiple hosts with separate
      certs are required.

      Management via the CLI:
          iam-ra host onboard <host> --role X --role Y    # multi-role onboard
          iam-ra host add-role <host> <role>              # attach a role
          iam-ra host remove-role <host> <role>           # detach a role
          iam-ra host rotate-cert <host>                  # renew cert, keep roles

      The CLI writes the profile ARN map into the v2 SOPS file at
      secrets/hosts/<host>/iam-ra.yaml (nested `profiles` key). The ARNs
      are not secrets and can be pasted into Nix directly from
      `iam-ra host onboard --json`.
    '';
    example = lib.literalExpression ''
      {
        admin = {
          profileArn = "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/admin";
          roleArn = "arn:aws:iam::123456789012:role/admin";
          makeDefault = true;
        };
        readonly = {
          profileArn = "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/readonly";
          roleArn = "arn:aws:iam::123456789012:role/readonly";
        };
      }
    '';
  };
}
