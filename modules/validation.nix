# IAM Roles Anywhere - Validation
#
# ARN validation assertions and configuration warnings.
# This is a pure function that takes config values and lib functions,
# returning assertions and warnings for the module.
{ lib, cfg, iamRaLib }:

{
  assertions = [
    {
      assertion = iamRaLib.isValidTrustAnchorArn cfg.aws.trustAnchorArn;
      message = "programs.iamRolesAnywhere.aws.trustAnchorArn must be a valid IAM Roles Anywhere trust anchor ARN";
    }
    {
      assertion = iamRaLib.isValidProfileArn cfg.aws.profileArn;
      message = "programs.iamRolesAnywhere.aws.profileArn must be a valid IAM Roles Anywhere profile ARN";
    }
    {
      assertion = iamRaLib.isValidRoleArn cfg.aws.roleArn;
      message = "programs.iamRolesAnywhere.aws.roleArn must be a valid IAM role ARN";
    }
  ];

  warnings =
    [ ]
    ++ lib.optional (cfg.awsProfile.name == "default" && !cfg.awsProfile.makeDefault)
      "programs.iamRolesAnywhere: Profile name is 'default' but makeDefault is false. Consider setting makeDefault = true."
    ++ lib.optional (cfg.aws.sessionDuration != null && cfg.aws.sessionDuration < 900)
      "programs.iamRolesAnywhere: Session duration less than 900 seconds may cause issues.";
}
