# IAM Roles Anywhere - AWS CLI Profile Configuration
#
# Configures programs.awscli.settings with the credential_process command.
# This is a pure function that takes config values and returns a config fragment.
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
    # Don't install awscli2 again - packages.nix handles that
    package = lib.mkDefault null;
    settings = lib.mkMerge [
      namedProfile
      defaultProfile
    ];
  };
}
