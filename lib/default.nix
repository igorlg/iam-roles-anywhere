# IAM Roles Anywhere Library
#
# Core helper functions for IAM Roles Anywhere module.
# Only includes functions that are actively used by the modules.
{ lib }:

rec {
  # ===================
  # CREDENTIAL PROCESS
  # ===================

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
      baseCmd = [
        signingHelperPath
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
    lib.concatStringsSep " " (baseCmd ++ regionArgs ++ durationArgs);

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
