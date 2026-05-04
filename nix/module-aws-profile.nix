# IAM Roles Anywhere - AWS CLI Profile Configuration
#
# Configures programs.awscli.settings with credential_process commands
# for every profile across every identity.
#
# Identities: each has its own cert + trust anchor + region. Profiles
# within an identity share those. The generated AWS CLI has a single
# flat profile namespace, so we flatten `cfg.identities.<name>.profiles`
# into one attrset keyed by awsProfileName (uniqueness enforced in
# module-validation.nix).
{
  lib,
  cfg,
  pkgs,
  mkCredentialProcessCommand,
}:

let
  # Build credential_process command for a specific profile within a
  # specific identity.
  mkCredentialProcess =
    identityCfg: profileCfg:
    mkCredentialProcessCommand {
      signingHelperPath = "${pkgs.aws-signing-helper}/bin/aws_signing_helper";
      certificatePath = toString identityCfg.certificate.certPath;
      privateKeyPath = toString identityCfg.certificate.keyPath;
      trustAnchorArn = identityCfg.trustAnchorArn;
      profileArn = profileCfg.profileArn;
      roleArn = profileCfg.roleArn;
      region = identityCfg.region;
      # Per-profile sessionDuration overrides identity default.
      sessionDuration =
        if profileCfg.sessionDuration != null then
          profileCfg.sessionDuration
        else
          identityCfg.sessionDuration;
    };

  # Build AWS CLI config entry for one profile within one identity.
  mkProfileConfig =
    identityCfg: profileCfg:
    {
      credential_process = mkCredentialProcess identityCfg profileCfg;
      region = identityCfg.region;
      output = profileCfg.output;
    }
    // profileCfg.extraConfig;

  # Flatten identities' profiles into a list of
  # { awsProfileName, identityCfg, profileCfg, makeDefault } records.
  # One record per profile, carrying a pointer to its identity so the
  # credential_process has the right cert and trust anchor.
  allProfileRecords = lib.concatLists (
    lib.mapAttrsToList (
      _identityName: identityCfg:
      lib.mapAttrsToList (_profileName: profileCfg: {
        inherit identityCfg profileCfg;
        inherit (profileCfg) awsProfileName makeDefault;
      }) identityCfg.profiles
    ) cfg.identities
  );

  # Named profile entries: one [profile <awsProfileName>] section per
  # profile across all identities. Uniqueness of awsProfileName is an
  # assertion in module-validation.nix, so listToAttrs is safe here
  # modulo that assertion.
  namedProfiles = lib.listToAttrs (
    map (rec_: {
      name = "profile ${rec_.awsProfileName}";
      value = mkProfileConfig rec_.identityCfg rec_.profileCfg;
    }) allProfileRecords
  );

  # [default] profile: the single record (across all identities) with
  # makeDefault = true, if any. validation asserts <=1 globally so
  # picking the first is deterministic even if the assertion weren't
  # there.
  defaultRecords = lib.filter (r: r.makeDefault) allProfileRecords;
  defaultProfileConfig =
    if defaultRecords != [ ] then
      let
        firstDefault = lib.head defaultRecords;
      in
      {
        default = mkProfileConfig firstDefault.identityCfg firstDefault.profileCfg;
      }
    else
      { };

  # True iff any identity defines at least one profile. Controls
  # whether programs.awscli gets enabled at all.
  hasAnyProfile = allProfileRecords != [ ];
in
{
  programs.awscli = lib.mkIf hasAnyProfile {
    enable = true;
    # Let home-manager handle package installation (defaults to awscli2)
    settings = lib.mkMerge [
      namedProfiles
      defaultProfileConfig
    ];
  };
}
