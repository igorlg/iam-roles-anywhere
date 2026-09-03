# macOS Keychain Key Store (Darwin only)
#
# Keeps the private key in a macOS keychain, marked non-extractable. The
# key cannot be copied off the host even by a process running as you -
# `security export` refuses. Compare ./minimal.nix, where the key is a
# 0600 file that any process running as the user can read.
#
# What this protects against: backup theft, an `scp` of your home
# directory, a sync client, an attacker with file-read but not execution.
# What it does NOT protect against: an attacker who can execute code as
# you, since they can invoke the credential helper just as you do.
#
# Prerequisites:
#   iam-ra init
#   iam-ra role create admin --policy arn:aws:iam::aws:policy/AdministratorAccess
#   iam-ra host enroll mbp --role admin --key-store macosKeychain
#
# This module refuses to evaluate on Linux: the credential helper's
# certificate-store support is a compile-time refusal stub there, so
# there is nothing to select against.
#
{ ... }:
{
  programs.iamRolesAnywhere = {
    enable = true;

    identities.default = {
      # Note there are no paths here. `source = "macosKeychain"` selects
      # an identity already in the keychain, and the helper's
      # --cert-selector is mutually exclusive with --certificate and
      # --private-key, which is why this is a tagged union rather than a
      # set of optional fields.
      certificate = {
        source = "macosKeychain";

        # Match on the certificate subject. `iam-ra` issues certificates
        # whose CN is the hostname you enrolled, so this is the stable
        # choice - it survives rotation, unlike `serial`.
        #
        # Matching is exact against the full DN, so "CN=mbp" matches only
        # a subject consisting of exactly that one RDN.
        selector.subject = "CN=mbp";

        # Alternatives (at least one selector must be set):
        #
        #   selector.issuer = "CN=IAM Roles Anywhere CA (default/default)";
        #
        #   Pins one exact certificate, so it must be updated on every
        #   rotation. Prefer `subject` unless you need to disambiguate:
        #   selector.serial = "15D19632234BF759A32802C0DA88F9E8AFC8702D";
      };

      trustAnchorArn = "arn:aws:rolesanywhere:ap-southeast-2:123456789012:trust-anchor/abc123";
      region = "ap-southeast-2";

      profiles.admin = {
        profileArn = "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/admin-profile";
        roleArn = "arn:aws:iam::123456789012:role/iam-ra-admin";
        makeDefault = true;
      };
    };
  };
}

# Operational notes:
#
#   One keychain per machine at ~/Library/Keychains/iam-ra.keychain,
#   holding as many host identities as you enrol, each selected by CN.
#
#   Its password is generated and stored in your login keychain, so it
#   unlocks automatically once you log in. Auto-relock is disabled on it,
#   because otherwise credential fetches start failing about five minutes
#   after login.
#
#   To inspect:
#     security find-identity ~/Library/Keychains/iam-ra.keychain
#
#   Do NOT pass -v. It filters to certificates with a system-trusted
#   chain, which a self-signed IAM RA CA is not, so it reports nothing.
#   CSSMERR_TP_NOT_TRUSTED in that output is expected and harmless - the
#   chain is validated by IAM Roles Anywhere against the trust anchor,
#   not by macOS.
