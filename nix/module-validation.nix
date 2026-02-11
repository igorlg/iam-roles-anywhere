# IAM Roles Anywhere - Validation
#
# ARN validation assertions and configuration warnings.
# Validates both shared config and each profile's ARNs.
{
  lib,
  cfg,
  iamRaLib,
}:

let
  # Validate a single profile's ARNs
  profileAssertions = name: profileCfg: [
    {
      assertion = iamRaLib.isValidProfileArn profileCfg.profileArn;
      message = "programs.iamRolesAnywhere.profiles.${name}.profileArn must be a valid IAM Roles Anywhere profile ARN";
    }
    {
      assertion = iamRaLib.isValidRoleArn profileCfg.roleArn;
      message = "programs.iamRolesAnywhere.profiles.${name}.roleArn must be a valid IAM role ARN";
    }
  ];

  # Flatten assertions for all profiles
  allProfileAssertions = lib.flatten (lib.mapAttrsToList profileAssertions cfg.profiles);

  # Check for multiple makeDefault = true
  defaultCount = lib.length (lib.filter (p: p.makeDefault) (lib.attrValues cfg.profiles));

  # Validate session duration for each profile
  profileDurationWarnings = lib.mapAttrsToList (
    name: profileCfg:
    lib.optional (profileCfg.sessionDuration != null && profileCfg.sessionDuration < 900)
      "programs.iamRolesAnywhere.profiles.${name}: Session duration less than 900 seconds may cause issues."
  ) cfg.profiles;

in
{
  assertions = [
    # Shared trust anchor validation
    {
      assertion = iamRaLib.isValidTrustAnchorArn cfg.trustAnchorArn;
      message = "programs.iamRolesAnywhere.trustAnchorArn must be a valid IAM Roles Anywhere trust anchor ARN";
    }
    # At least one profile must be defined
    {
      assertion = cfg.profiles != { };
      message = "programs.iamRolesAnywhere: At least one profile must be defined in 'profiles'";
    }
    # Only one profile can be default
    {
      assertion = defaultCount <= 1;
      message = "programs.iamRolesAnywhere: Only one profile can have makeDefault = true (found ${toString defaultCount})";
    }
  ]
  ++ allProfileAssertions;

  warnings =
    [ ]
    # Global session duration warning
    ++ lib.optional (
      cfg.sessionDuration != null && cfg.sessionDuration < 900
    ) "programs.iamRolesAnywhere: Global session duration less than 900 seconds may cause issues."
    # Per-profile session duration warnings
    ++ lib.flatten profileDurationWarnings;
}
