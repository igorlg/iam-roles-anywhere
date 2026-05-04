# IAM Roles Anywhere - Validation
#
# Assertions and warnings for the identities attrset.
#
# Layers:
#   1. Global: at least one identity; unique awsProfileName; at most one makeDefault
#   2. Per-identity: valid trustAnchorArn; at least one profile
#   3. Per-profile: valid profileArn and roleArn
#
# Negative tests in checks.nix exercise the global assertions by
# grepping for substrings of the error messages, so the exact wording
# here forms part of the module's contract. Be careful when rewording.
{
  lib,
  cfg,
  iamRaLib,
}:

let
  # ---------- Per-profile (within a single identity) ----------

  profileAssertions = identityName: profileName: profileCfg: [
    {
      assertion = iamRaLib.isValidProfileArn profileCfg.profileArn;
      message = "programs.iamRolesAnywhere.identities.${identityName}.profiles.${profileName}.profileArn must be a valid IAM Roles Anywhere profile ARN";
    }
    {
      assertion = iamRaLib.isValidRoleArn profileCfg.roleArn;
      message = "programs.iamRolesAnywhere.identities.${identityName}.profiles.${profileName}.roleArn must be a valid IAM role ARN";
    }
  ];

  # ---------- Per-identity ----------

  identityAssertions =
    identityName: identityCfg:
    [
      {
        assertion = iamRaLib.isValidTrustAnchorArn identityCfg.trustAnchorArn;
        message = "programs.iamRolesAnywhere.identities.${identityName}.trustAnchorArn must be a valid IAM Roles Anywhere trust anchor ARN";
      }
      {
        assertion = identityCfg.profiles != { };
        message = "programs.iamRolesAnywhere.identities.${identityName}: at least one profile must be defined under 'profiles'";
      }
    ]
    ++ lib.flatten (
      lib.mapAttrsToList (
        profileName: profileCfg: profileAssertions identityName profileName profileCfg
      ) identityCfg.profiles
    );

  allIdentityAssertions = lib.flatten (lib.mapAttrsToList identityAssertions cfg.identities);

  # ---------- Global ----------

  # Flatten all profiles across identities into a list of records so we
  # can assert on cross-identity properties (name uniqueness, single default).
  allProfileRecords = lib.concatLists (
    lib.mapAttrsToList (
      identityName: identityCfg:
      lib.mapAttrsToList (profileName: profileCfg: {
        inherit
          identityName
          profileName
          profileCfg
          ;
        inherit (profileCfg) awsProfileName makeDefault;
      }) identityCfg.profiles
    ) cfg.identities
  );

  awsProfileNames = map (r: r.awsProfileName) allProfileRecords;
  duplicateAwsProfileNames = lib.unique (
    lib.filter (n: (lib.count (x: x == n) awsProfileNames) > 1) awsProfileNames
  );

  defaultCount = lib.count (r: r.makeDefault) allProfileRecords;

  globalAssertions = [
    {
      assertion = cfg.identities != { };
      message = "programs.iamRolesAnywhere: At least one identity must be defined in 'identities' when the module is enabled";
    }
    {
      assertion = duplicateAwsProfileNames == [ ];
      message =
        "programs.iamRolesAnywhere: awsProfileName must be unique across all identities. "
        + "Duplicates found: ${lib.concatStringsSep ", " duplicateAwsProfileNames}. "
        + "Set awsProfileName explicitly on the conflicting profiles, or rename them.";
    }
    {
      assertion = defaultCount <= 1;
      message = "programs.iamRolesAnywhere: Only one profile can have makeDefault = true across all identities (found ${toString defaultCount})";
    }
  ];

  # ---------- Warnings ----------

  # Per-identity session duration warning
  identitySessionWarnings = lib.flatten (
    lib.mapAttrsToList (
      identityName: identityCfg:
      lib.optional (identityCfg.sessionDuration != null && identityCfg.sessionDuration < 900)
        "programs.iamRolesAnywhere.identities.${identityName}: sessionDuration less than 900 seconds may cause issues."
    ) cfg.identities
  );

  # Per-profile session duration warning
  profileSessionWarnings = lib.flatten (
    lib.mapAttrsToList (
      identityName: identityCfg:
      lib.mapAttrsToList (
        profileName: profileCfg:
        lib.optional (profileCfg.sessionDuration != null && profileCfg.sessionDuration < 900)
          "programs.iamRolesAnywhere.identities.${identityName}.profiles.${profileName}: sessionDuration less than 900 seconds may cause issues."
      ) identityCfg.profiles
    ) cfg.identities
  );
in
{
  assertions = globalAssertions ++ allIdentityAssertions;
  warnings = lib.flatten (identitySessionWarnings ++ profileSessionWarnings);
}
