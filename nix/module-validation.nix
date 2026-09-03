# IAM Roles Anywhere - Validation
#
# Assertions and warnings for the identities attrset.
#
# Layers:
#   1. Global: at least one identity; unique awsProfileName; at most one makeDefault
#   2. Per-identity: valid trustAnchorArn; at least one profile; certificate
#      source completeness, mutual exclusion, and platform support
#   3. Per-profile: valid profileArn and roleArn
#
# Negative tests in checks.nix exercise the global assertions by
# grepping for substrings of the error messages, so the exact wording
# here forms part of the module's contract. Be careful when rewording.
{
  lib,
  cfg,
  iamRaLib,
  isDarwin,
}:

let
  # ---------- Per-identity certificate source ----------

  # The certificate option is a tagged union (see module-options.nix).
  # Nix's module system cannot express "these fields are required only
  # for this tag", so completeness and mutual exclusion are enforced
  # here instead of in the type.
  certificateAssertions =
    identityName: identityCfg:
    let
      cert = identityCfg.certificate;
      inherit (cert) source;
      opt = "programs.iamRolesAnywhere.identities.${identityName}.certificate";
      selectorSet =
        cert.selector.subject != null || cert.selector.issuer != null || cert.selector.serial != null;
      pathsSet = cert.certPath != null || cert.keyPath != null;
    in
    lib.optionals (source == "files") [
      {
        assertion = cert.certPath != null;
        message = "${opt}.certPath is required when ${opt}.source = \"files\"";
      }
      {
        assertion = cert.keyPath != null;
        message = "${opt}.keyPath is required when ${opt}.source = \"files\"";
      }
      {
        assertion = !selectorSet;
        message =
          "${opt}.selector is set but ${opt}.source = \"files\", so it would be silently "
          + "ignored. Set source = \"macosKeychain\" to use the selector, or remove it.";
      }
    ]
    ++ lib.optionals (source == "macosKeychain") [
      {
        # Without this the selector matches every identity in the
        # keychain, and the helper fails on an ambiguous match.
        assertion = selectorSet;
        message =
          "${opt}.source = \"macosKeychain\" requires at least one of "
          + "${opt}.selector.{subject,issuer,serial}";
      }
      {
        # aws_signing_helper marks --cert-selector mutually exclusive
        # with both --certificate and --private-key, so a config setting
        # both would fail at runtime with an argument-parse error.
        assertion = !pathsSet;
        message =
          "${opt}.certPath/keyPath cannot be combined with source = \"macosKeychain\". "
          + "aws_signing_helper treats --cert-selector as mutually exclusive with "
          + "--certificate and --private-key. Remove the paths.";
      }
      {
        # The credential helper's certificate-store support is a stub
        # returning "unable to use cert store signer on linux", so this
        # would build fine and then fail at every credential fetch.
        # Fail at eval time instead.
        assertion = isDarwin;
        message =
          "${opt}.source = \"macosKeychain\" is only supported on Darwin. "
          + "aws_signing_helper has no certificate-store implementation on Linux - it "
          + "returns \"unable to use cert store signer on linux\" at runtime. Use "
          + "source = \"files\" instead.";
      }
    ];

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
    ++ certificateAssertions identityName identityCfg
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
