# IAM Roles Anywhere Library
#
# Core helper functions for IAM Roles Anywhere module.
# Only includes functions that are actively used by the modules.
{ lib }:

rec {
  # ===================
  # CREDENTIAL PROCESS
  # ===================

  # Assemble the argv (excluding the helper binary) that runs the
  # aws_signing_helper credential-process subcommand. Factored out so
  # both the inline command (mkCredentialProcessCommand) and the
  # wrapper-script variant (mkCredentialProcessScript) share one
  # source of truth for the argument order / conditional args.
  mkCredentialProcessArgs =
    {
      certificatePath,
      privateKeyPath,
      trustAnchorArn,
      profileArn,
      roleArn,
      region ? null,
      sessionDuration ? null,
    }:
    let
      baseArgs = [
        "credential-process"
        "--certificate"
        certificatePath
        "--private-key"
        privateKeyPath
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
  mkCredentialProcessCommand =
    {
      signingHelperPath, # Path to aws_signing_helper binary
      certificatePath, # Path to X.509 certificate
      privateKeyPath, # Path to private key
      trustAnchorArn, # IAM Roles Anywhere trust anchor ARN
      profileArn, # IAM Roles Anywhere profile ARN
      roleArn, # IAM role ARN to assume
      region ? null, # Optional: AWS region
      sessionDuration ? null, # Optional: Session duration in seconds
    }:
    let
      args = mkCredentialProcessArgs {
        inherit
          certificatePath
          privateKeyPath
          trustAnchorArn
          profileArn
          roleArn
          region
          sessionDuration
          ;
      };
    in
    lib.concatStringsSep " " ([ signingHelperPath ] ++ args);

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
  #
  # With privateKeyRef (a 1Password `op://` reference) instead of
  # privateKeyPath, the key is read once with `op read` and served on a
  # FIFO by keyServePath (nix/keyserve.nix; callers build it, as this
  # file only takes `lib`). See keyRefPrelude.
  mkCredentialProcessScript =
    {
      signingHelperPath,
      certificatePath,
      privateKeyPath ? null,
      privateKeyRef ? null,
      opPath ? "op",
      keyServePath ? null,
      trustAnchorArn,
      profileArn,
      roleArn,
      region ? null,
      sessionDuration ? null,
    }:
    assert lib.assertMsg (
      (privateKeyPath == null) != (privateKeyRef == null)
    ) "mkCredentialProcessScript: exactly one of privateKeyPath and privateKeyRef must be set";
    let
      useKeyRef = privateKeyRef != null;
      args = mkCredentialProcessArgs {
        # keyRef: the FIFO path, left unquoted below so the shell expands it.
        privateKeyPath = if useKeyRef then ''"$dir/key"'' else privateKeyPath;
        inherit
          certificatePath
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
        "${lib.escapeShellArg flag} ${
          if useKeyRef && flag == "--private-key" then value else lib.escapeShellArg value
        }"
      ) pairCount;
      bodyLines = [ (lib.escapeShellArg subcommand) ] ++ pairLines;
      body = lib.concatStringsSep " \\\n  " bodyLines;

      # aws_signing_helper opens --private-key 11-21 times per run, so a
      # one-shot <(op read ...) breaks it. Read the key once and pipe it
      # (printf is a builtin: no argv) to keyserve, which writes a whole
      # copy per open of a FIFO in a 0700 mktemp dir; the key never
      # touches disk. `exec` keeps $$, so keyserve removes the dir and
      # exits once the helper is gone, even after SIGKILL. $(...) strips
      # the PEM's trailing newline; printf restores it. bash-3.2-safe.
      keyRefPrelude = lib.optionalString useKeyRef ''
        ref=${lib.escapeShellArg privateKeyRef}
        key=$(${lib.escapeShellArg opPath} read "$ref") && [[ $key == *"-----BEGIN "* ]] ||
          { echo "iam-ra: no PEM private key from 1Password ($ref); is it unlocked?" >&2; exit 1; }
        dir=$(mktemp -d "''${TMPDIR:-/tmp}/iam-ra.XXXXXX") && mkfifo -m 600 "$dir/key" || exit 1
        printf '%s\n' "$key" | ${lib.escapeShellArg keyServePath} "$dir/key" "$$" >/dev/null &
      '';
    in
    ''
      #!/usr/bin/env bash
      # Generated by programs.iamRolesAnywhere (Nix module).
      # DO NOT EDIT - regenerated by home-manager on every activation.
    ''
    + keyRefPrelude
    + ''
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
