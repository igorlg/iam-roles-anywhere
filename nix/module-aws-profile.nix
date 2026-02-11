# IAM Roles Anywhere - AWS CLI Profile Configuration
#
# Configures programs.awscli.settings with credential_process commands
# for each defined profile.
#
# Generates multiple AWS CLI profiles from the profiles attrset,
# each with its own credential_process pointing to the appropriate role.
{
  lib,
  cfg,
  pkgs,
  mkCredentialProcessCommand,
}:

let
  # Build credential_process command for a specific profile
  mkCredentialProcess =
    profileCfg:
    mkCredentialProcessCommand {
      signingHelperPath = "${pkgs.aws-signing-helper}/bin/aws_signing_helper";
      certificatePath = toString cfg.certificate.certPath;
      privateKeyPath = toString cfg.certificate.keyPath;
      trustAnchorArn = cfg.trustAnchorArn;
      profileArn = profileCfg.profileArn;
      roleArn = profileCfg.roleArn;
      region = cfg.region;
      # Per-profile sessionDuration overrides global
      sessionDuration =
        if profileCfg.sessionDuration != null then profileCfg.sessionDuration else cfg.sessionDuration;
    };

  # Build AWS CLI config for a single profile
  mkProfileConfig =
    name: profileCfg:
    {
      credential_process = mkCredentialProcess profileCfg;
      region = cfg.region;
      output = profileCfg.output;
    }
    // profileCfg.extraConfig;

  # Generate all named profiles
  # Each profile gets a "profile <name>" entry in AWS config
  namedProfiles = lib.mapAttrs' (
    name: profileCfg:
    lib.nameValuePair "profile ${profileCfg.awsProfileName}" (mkProfileConfig name profileCfg)
  ) cfg.profiles;

  # Find profiles with makeDefault = true and create [default] entry
  # (only the first one if multiple are set - validation warns about this)
  defaultProfiles = lib.filterAttrs (_: p: p.makeDefault) cfg.profiles;
  defaultProfileConfig =
    if defaultProfiles != { } then
      let
        firstDefault = lib.head (lib.attrValues defaultProfiles);
      in
      {
        default = mkProfileConfig "default" firstDefault;
      }
    else
      { };

in
{
  programs.awscli = lib.mkIf (cfg.profiles != { }) {
    enable = true;
    # Let home-manager handle package installation (defaults to awscli2)
    settings = lib.mkMerge [
      namedProfiles
      defaultProfileConfig
    ];
  };
}
