# IAM Roles Anywhere Library - Unused/Reserved Functions
#
# These functions were originally implemented but are not currently used
# by the modules. They are preserved here for potential future use.
#
# To use any of these, move them back to default.nix and update the
# modules that need them.
{ lib }:

rec {
  # ===================
  # CA MODES
  # ===================
  # Planned for CLI integration - not currently used by Nix modules.

  caModes = {
    self-managed = {
      description = "Self-managed CA - you control the CA certificate and key";
      trustAnchorType = "CERTIFICATE_BUNDLE";
    };
    aws-pca = {
      description = "AWS Private CA - managed by ACM Private CA";
      trustAnchorType = "AWS_ACM_PCA";
    };
  };

  validCaModes = builtins.attrNames caModes;

  # ===================
  # AWS CONFIG GENERATION
  # ===================
  # These generate raw config file content. The modules now use
  # programs.awscli.settings instead, which is more composable.

  # Generate an AWS config profile section
  mkAwsConfigProfile =
    {
      profileName,
      credentialProcess,
      region,
      output ? "json",
      extraConfig ? { },
    }:
    let
      baseConfig = {
        credential_process = credentialProcess;
        region = region;
        output = output;
      };
      mergedConfig = baseConfig // extraConfig;
      configLines = lib.mapAttrsToList (k: v: "${k} = ${toString v}") mergedConfig;
    in
    ''
      [profile ${profileName}]
      ${lib.concatStringsSep "\n" configLines}
    '';

  # Generate a default profile section
  mkAwsConfigDefault =
    {
      credentialProcess,
      region,
      output ? "json",
      extraConfig ? { },
    }:
    let
      baseConfig = {
        credential_process = credentialProcess;
        region = region;
        output = output;
      };
      mergedConfig = baseConfig // extraConfig;
      configLines = lib.mapAttrsToList (k: v: "${k} = ${toString v}") mergedConfig;
    in
    ''
      [default]
      ${lib.concatStringsSep "\n" configLines}
    '';

  # ===================
  # GENERIC VALIDATION
  # ===================

  # Generic ARN validation (less specific than the typed validators)
  isValidArn =
    arn:
    builtins.match "arn:aws[a-z-]*:[a-z0-9-]+:[a-z0-9-]*:[0-9]*:.+" arn != null;

  # ===================
  # ARN PARSING HELPERS
  # ===================

  # Extract AWS account ID from an ARN
  getAccountIdFromArn =
    arn:
    let
      parts = lib.splitString ":" arn;
    in
    if builtins.length parts >= 5 then builtins.elemAt parts 4 else null;

  # Extract AWS region from an ARN
  getRegionFromArn =
    arn:
    let
      parts = lib.splitString ":" arn;
    in
    if builtins.length parts >= 4 then builtins.elemAt parts 3 else null;

  # ===================
  # PROFILES (Future use)
  # ===================
  # Predefined configuration profiles for common use cases.
  # Intended for CLI or higher-level configuration helpers.

  profiles = {
    basic = {
      description = "Basic profile with minimal permissions";
      sessionDuration = 3600;
      recommendedPolicies = [ "sts:GetCallerIdentity" ];
    };

    server = {
      description = "Server profile with CloudWatch and S3 backup access";
      sessionDuration = 3600;
      recommendedPolicies = [
        "sts:GetCallerIdentity"
        "logs:*"
        "s3:GetObject"
        "s3:PutObject"
      ];
    };

    admin = {
      description = "Admin profile - use with caution";
      sessionDuration = 900;
      recommendedPolicies = [ "*" ];
    };
  };

  profileNames = builtins.attrNames profiles;
}
