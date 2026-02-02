# IAM Roles Anywhere - Option Definitions
#
# Pure option definitions for the IAM Roles Anywhere module.
# This file defines the API surface - no implementation logic.
#
# Used by both home-manager and system-level modules.
{ lib }:

{
  enable = lib.mkEnableOption "IAM Roles Anywhere authentication";

  # ===================
  # CERTIFICATE PATHS
  # ===================
  # These are paths to where certificates are deployed.
  # This module is secrets-manager agnostic - paths can come from:
  #   - SOPS: config.sops.secrets."iam-ra/cert".path
  #   - agenix: config.age.secrets.iam-ra-cert.path
  #   - Static files: "/etc/ssl/iam-ra/cert.pem"
  #   - Any other source

  certificate = {
    certPath = lib.mkOption {
      type = lib.types.either lib.types.path lib.types.str;
      description = ''
        Path to the X.509 certificate file (PEM format).
        Can be a static path or a reference to a secrets manager path.
      '';
      example = "/run/secrets/iam-ra/cert.pem";
    };

    keyPath = lib.mkOption {
      type = lib.types.either lib.types.path lib.types.str;
      description = ''
        Path to the private key file (PEM format).
        Can be a static path or a reference to a secrets manager path.
      '';
      example = "/run/secrets/iam-ra/key.pem";
    };
  };

  # ===================
  # AWS CONFIGURATION
  # ===================

  aws = {
    region = lib.mkOption {
      type = lib.types.str;
      description = "AWS region for API calls";
      example = "ap-southeast-2";
    };

    trustAnchorArn = lib.mkOption {
      type = lib.types.str;
      description = "ARN of the IAM Roles Anywhere trust anchor";
      example = "arn:aws:rolesanywhere:ap-southeast-2:123456789012:trust-anchor/abc123";
    };

    profileArn = lib.mkOption {
      type = lib.types.str;
      description = "ARN of the IAM Roles Anywhere profile";
      example = "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/def456";
    };

    roleArn = lib.mkOption {
      type = lib.types.str;
      description = "ARN of the IAM role to assume";
      example = "arn:aws:iam::123456789012:role/my-host-rolesanywhere";
    };

    sessionDuration = lib.mkOption {
      type = lib.types.nullOr lib.types.int;
      default = null;
      description = "Session duration in seconds (default: 3600)";
      example = 3600;
    };
  };

  # ===================
  # AWS PROFILE CONFIG
  # ===================

  awsProfile = {
    name = lib.mkOption {
      type = lib.types.str;
      default = "iam-ra";
      description = "Name of the AWS CLI profile to create";
      example = "rolesanywhere";
    };

    makeDefault = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        If true, also configure the [default] profile with the same settings.
        This allows using AWS CLI without specifying --profile.
      '';
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
      description = "Additional configuration options for the profile";
      example = {
        cli_pager = "";
        retry_mode = "standard";
      };
    };
  };
}
