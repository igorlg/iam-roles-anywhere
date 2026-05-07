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
#
# Output format is switched by cfg.useCredentialProcessWrapper:
#   - false (default): credential_process is the full inline command
#   - true:            credential_process is a path to
#                      ~/.aws/iam-ra/<awsProfileName>.sh, and a
#                      matching `home.file` entry installs the wrapper
#                      script at that path (via home-manager symlink
#                      into /nix/store).
{
  lib,
  cfg,
  config,
  pkgs,
  mkCredentialProcessCommand,
  mkCredentialProcessScript,
}:

let
  signingHelperPath = "${pkgs.aws-signing-helper}/bin/aws_signing_helper";

  # Resolve a profile's effective session duration (profile override
  # falling back to identity default, possibly null).
  effectiveSessionDuration =
    identityCfg: profileCfg:
    if profileCfg.sessionDuration != null then
      profileCfg.sessionDuration
    else
      identityCfg.sessionDuration;

  # Bundle the args every credential-process variant needs.
  credProcessArgs = identityCfg: profileCfg: {
    inherit signingHelperPath;
    certificatePath = toString identityCfg.certificate.certPath;
    privateKeyPath = toString identityCfg.certificate.keyPath;
    trustAnchorArn = identityCfg.trustAnchorArn;
    profileArn = profileCfg.profileArn;
    roleArn = profileCfg.roleArn;
    region = identityCfg.region;
    sessionDuration = effectiveSessionDuration identityCfg profileCfg;
  };

  # Inline credential_process command (legacy path, default behaviour).
  mkCredentialProcess =
    identityCfg: profileCfg: mkCredentialProcessCommand (credProcessArgs identityCfg profileCfg);

  # Absolute path to a profile's wrapper script. AWS CLI's
  # credential_process does NOT perform shell variable expansion, so
  # the path must be fully resolved at Nix eval time.
  wrapperScriptPath = awsProfileName: "${config.home.homeDirectory}/.aws/iam-ra/${awsProfileName}.sh";

  # Relative key used in home.file (home-manager prefixes $HOME).
  wrapperScriptHomeFileKey = awsProfileName: ".aws/iam-ra/${awsProfileName}.sh";

  # credential_process value to write into ~/.aws/config. Either the
  # wrapper path or the inline command, depending on the flag.
  mkCredentialProcessValue =
    identityCfg: profileCfg:
    if cfg.useCredentialProcessWrapper then
      wrapperScriptPath profileCfg.awsProfileName
    else
      mkCredentialProcess identityCfg profileCfg;

  # Build AWS CLI config entry for one profile within one identity.
  mkProfileConfig =
    identityCfg: profileCfg:
    {
      credential_process = mkCredentialProcessValue identityCfg profileCfg;
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

  # home.file entries for the wrapper scripts - one per profile,
  # only when the feature is enabled. Uses home-manager's managed
  # symlinks, so the script content is declarative and immutable
  # (users can cat the path but not edit in place).
  wrapperScriptHomeFiles = lib.listToAttrs (
    map (rec_: {
      name = wrapperScriptHomeFileKey rec_.awsProfileName;
      value = {
        executable = true;
        text = mkCredentialProcessScript (credProcessArgs rec_.identityCfg rec_.profileCfg);
      };
    }) allProfileRecords
  );

  # True iff any identity defines at least one profile. Controls
  # whether programs.awscli gets enabled at all.
  hasAnyProfile = allProfileRecords != [ ];
in
lib.mkMerge [
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
  (lib.mkIf (hasAnyProfile && cfg.useCredentialProcessWrapper) {
    home.file = wrapperScriptHomeFiles;
  })
]
