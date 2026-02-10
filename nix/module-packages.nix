# IAM Roles Anywhere - Package Installation
#
# Returns the set of packages required for IAM Roles Anywhere authentication.
# This is a pure function that takes pkgs and returns a config fragment.
#
# Note: awscli2 is NOT installed here - it's handled by programs.awscli in
# module-aws-profile.nix. This avoids conflicts with user's existing awscli config.
{ pkgs }:

{
  # Install required packages:
  # - aws-signing-helper: credential process for IAM Roles Anywhere (required)
  # - openssl: for certificate debugging (checking expiry, subject, etc.)
  home.packages = [
    pkgs.aws-signing-helper
    pkgs.openssl
  ];
}
