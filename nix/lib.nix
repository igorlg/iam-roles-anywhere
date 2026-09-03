# IAM Roles Anywhere Library
#
# Core helper functions for IAM Roles Anywhere module.
# Only includes functions that are actively used by the modules.
{ lib }:

rec {
  # ===================
  # CERTIFICATE SOURCES
  # ===================

  # Supported certificate sources. Each names a different way of telling
  # aws_signing_helper where the identity lives.
  #
  #   files          --certificate <path> --private-key <path>
  #   macosKeychain  --cert-selector <selector>   (Darwin only)
  #
  # These are NOT combinable. aws_signing_helper declares
  # MarkFlagsMutuallyExclusive on ("certificate", "cert-selector") and on
  # ("private-key", "cert-selector"), so passing a path alongside a selector
  # is rejected at argument-parse time. That exclusivity is why a certificate
  # is modelled as a tagged union and why mkCertificateSourceArgs *dispatches*
  # on the tag rather than appending optional arguments.
  certificateSourceNames = [
    "files"
    "macosKeychain"
  ];

  # Render the value for --cert-selector.
  #
  # Format is one or more `Key=<key>,Value=<value>` pairs, space separated,
  # forming a SINGLE argument. Only three keys exist in the helper's
  # validCertSelectorKeys: x509Subject, x509Issuer, x509Serial. Matching is
  # exact full-DN string equality against Go's cert.Subject.String(), so a
  # bare "CN=foo" only matches a DN with exactly one RDN. Serial is base-16.
  mkCertSelectorValue =
    selector:
    let
      get = field: selector.${field} or null;
      pairs =
        lib.optional (get "subject" != null) "Key=x509Subject,Value=${selector.subject}"
        ++ lib.optional (get "issuer" != null) "Key=x509Issuer,Value=${selector.issuer}"
        ++ lib.optional (get "serial" != null) "Key=x509Serial,Value=${selector.serial}";
    in
    if pairs == [ ] then
      throw (
        "programs.iamRolesAnywhere: certificate.source = \"macosKeychain\" requires at least "
        + "one of certificate.selector.{subject,issuer,serial} to be set, otherwise the "
        + "selector would match every identity in the keychain."
      )
    else
      lib.concatStringsSep " " pairs;

  # Arguments identifying the certificate and key, dispatched on source.
  # Returns a disjoint argument set per source - never a union of both.
  mkCertificateSourceArgs =
    certificate:
    let
      source = certificate.source or "files";
    in
    if source == "files" then
      [
        "--certificate"
        (toString certificate.certPath)
        "--private-key"
        (toString certificate.keyPath)
      ]
    else if source == "macosKeychain" then
      [
        "--cert-selector"
        (mkCertSelectorValue (certificate.selector or { }))
      ]
    else
      throw (
        "programs.iamRolesAnywhere: unknown certificate.source \"${toString source}\"; "
        + "expected one of ${lib.concatStringsSep ", " certificateSourceNames}"
      );

  # ===================
  # CREDENTIAL PROCESS
  # ===================

  # Assemble the argv (excluding the helper binary) that runs the
  # aws_signing_helper credential-process subcommand. Factored out so
  # both the inline command (mkCredentialProcessCommand) and the
  # wrapper-script variant (mkCredentialProcessScript) share one
  # source of truth for the argument order / conditional args.
  #
  # `certificate` is the tagged union described above:
  #   { source = "files"; certPath = ...; keyPath = ...; }
  #   { source = "macosKeychain"; selector = { subject = ...; ... }; }
  mkCredentialProcessArgs =
    {
      certificate,
      trustAnchorArn,
      profileArn,
      roleArn,
      region ? null,
      sessionDuration ? null,
    }:
    let
      baseArgs = [
        "credential-process"
      ]
      ++ mkCertificateSourceArgs certificate
      ++ [
        "--trust-anchor-arn"
        trustAnchorArn
        "--profile-arn"
        profileArn
        "--role-arn"
        roleArn
      ];
      regionArgs = lib.optionals (region != null) [
        "--region"
        region
      ];
      durationArgs = lib.optionals (sessionDuration != null) [
        "--session-duration"
        (toString sessionDuration)
      ];
    in
    baseArgs ++ regionArgs ++ durationArgs;

  # Generate the aws_signing_helper credential-process command.
  # This command is used in ~/.aws/config to obtain temporary credentials.
  #
  # Every token is passed through lib.escapeShellArg. credential_process is
  # not run through a shell, but consumers split the string with POSIX
  # shell-word rules (botocore uses shlex.split via compat_shell_split), so
  # single-quoting is both understood and necessary: a --cert-selector value
  # contains spaces, and certificate paths may too. Without quoting such a
  # value would silently split into several arguments.
  #
  # escapeShellArg is a no-op for tokens of only [alnum,._+:@%/-], so plain
  # paths and ARNs come out unchanged and unquoted.
  mkCredentialProcessCommand =
    {
      signingHelperPath, # Path to aws_signing_helper binary
      certificate, # Tagged certificate source (see mkCertificateSourceArgs)
      trustAnchorArn, # IAM Roles Anywhere trust anchor ARN
      profileArn, # IAM Roles Anywhere profile ARN
      roleArn, # IAM role ARN to assume
      region ? null, # Optional: AWS region
      sessionDuration ? null, # Optional: Session duration in seconds
    }:
    let
      args = mkCredentialProcessArgs {
        inherit
          certificate
          trustAnchorArn
          profileArn
          roleArn
          region
          sessionDuration
          ;
      };
    in
    lib.concatStringsSep " " (map lib.escapeShellArg ([ signingHelperPath ] ++ args));

  # Generate a standalone shell script that invokes aws_signing_helper
  # credential-process. Emitted when useCredentialProcessWrapper is
  # enabled in the module, so ~/.aws/config stays readable instead of
  # containing a 500-character one-liner.
  #
  # Script properties:
  #   - `#!/usr/bin/env bash` shebang (portable across NixOS/Darwin)
  #   - `exec` so no extra shell process lingers past credential fetch
  #   - Every argument single-quoted via lib.escapeShellArg where
  #     needed (robust against paths/ARNs with shell metacharacters)
  #   - Flags paired with their values on the same line, one pair per
  #     line (readable when cat'd for debugging)
  #   - Self-identifying header comment pointing users back to Nix
  mkCredentialProcessScript =
    {
      signingHelperPath,
      certificate,
      trustAnchorArn,
      profileArn,
      roleArn,
      region ? null,
      sessionDuration ? null,
    }:
    let
      args = mkCredentialProcessArgs {
        inherit
          certificate
          trustAnchorArn
          profileArn
          roleArn
          region
          sessionDuration
          ;
      };
      # mkCredentialProcessArgs produces:
      #   [ "credential-process" "--flag1" value1 "--flag2" value2 ... ]
      # i.e. a lone subcommand followed by flag/value pairs. We split
      # them so each output line is either the subcommand or a
      # `--flag value` pair.
      subcommand = builtins.head args;
      flagValueList = lib.drop 1 args;
      pairCount = (builtins.length flagValueList) / 2;
      pairLines = builtins.genList (
        i:
        let
          flag = builtins.elemAt flagValueList (i * 2);
          value = builtins.elemAt flagValueList (i * 2 + 1);
        in
        "${lib.escapeShellArg flag} ${lib.escapeShellArg value}"
      ) pairCount;
      bodyLines = [ (lib.escapeShellArg subcommand) ] ++ pairLines;
      body = lib.concatStringsSep " \\\n  " bodyLines;
    in
    ''
      #!/usr/bin/env bash
      # Generated by programs.iamRolesAnywhere (Nix module).
      # DO NOT EDIT - regenerated by home-manager on every activation.
      exec ${lib.escapeShellArg signingHelperPath} \
        ${body}
    '';

  # ===================
  # ARN VALIDATION
  # ===================

  # Validate trust anchor ARN format
  isValidTrustAnchorArn =
    arn: builtins.match "arn:aws:rolesanywhere:[a-z0-9-]+:[0-9]+:trust-anchor/[a-f0-9-]+" arn != null;

  # Validate profile ARN format
  isValidProfileArn =
    arn: builtins.match "arn:aws:rolesanywhere:[a-z0-9-]+:[0-9]+:profile/[a-f0-9-]+" arn != null;

  # Validate IAM role ARN format
  isValidRoleArn = arn: builtins.match "arn:aws:iam::[0-9]+:role/.+" arn != null;
}
