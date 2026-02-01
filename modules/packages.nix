# IAM Roles Anywhere - Package Installation
#
# Returns the set of packages required for IAM Roles Anywhere authentication.
# This is a pure function that takes pkgs and returns a config fragment.
{ pkgs }:

{
  # Install required packages:
  # - aws-signing-helper: credential process for IAM Roles Anywhere
  # - awscli2: AWS CLI v2 to use the credentials
  # - openssl: for certificate debugging (checking expiry, subject, etc.)
  home.packages = [
    pkgs.aws-signing-helper
    pkgs.awscli2
    pkgs.openssl
  ];
}
