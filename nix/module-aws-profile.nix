# IAM Roles Anywhere - AWS CLI Profile Configuration
#
# Configures programs.awscli.settings with the credential_process command.
# This is a pure function that takes config values and returns a config fragment.
#
# Note: This enables programs.awscli which will install awscli2 by default.
# Users can override the package in their own config if needed.
{
  lib,
  cfg,
  credentialProcessCommand,
}:

let
  # Base profile configuration
  profileConfig = {
    credential_process = credentialProcessCommand;
    region = cfg.aws.region;
    output = cfg.awsProfile.output;
  }
  // cfg.awsProfile.extraConfig;

  # Named profile (e.g., "profile iam-ra")
  namedProfile = {
    "profile ${cfg.awsProfile.name}" = profileConfig;
  };

  # Default profile (optional)
  defaultProfile = lib.optionalAttrs cfg.awsProfile.makeDefault {
    default = profileConfig;
  };
in
{
  programs.awscli = {
    enable = true;
    # Let home-manager handle package installation (defaults to awscli2)
    # Users can override with: programs.awscli.package = pkgs.awscli;
    settings = lib.mkMerge [
      namedProfile
      defaultProfile
    ];
  };
}
