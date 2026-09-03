# IAM Roles Anywhere - Option Definitions
#
# Pure option definitions for the IAM Roles Anywhere module.
# This file defines the API surface - no implementation logic.
#
# Supports multiple identities (= AWS accounts / trust anchors), each
# holding its own certificate + trust anchor + region + set of profiles.
# Each profile within an identity assumes a different IAM role under
# that identity's trust anchor. The certificate is shared across all
# profiles WITHIN an identity (scenario 2: one host cert, many roles).
#
# For cross-account use (scenario 3: e.g. personal + work on one
# laptop) declare multiple identities, each with its own cert and
# trust anchor ARN. Profile names MUST be unique across all identities
# because they map to AWS CLI profile names in ~/.aws/config - the
# module-validation.nix file enforces this at eval time.
{ lib }:

let
  # Profile submodule - one entry per IAM role the identity can assume.
  profileSubmodule =
    { name, ... }:
    {
      options = {
        profileArn = lib.mkOption {
          type = lib.types.str;
          description = "ARN of the IAM Roles Anywhere profile";
          example = "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/def456";
        };

        roleArn = lib.mkOption {
          type = lib.types.str;
          description = "ARN of the IAM role to assume";
          example = "arn:aws:iam::123456789012:role/my-role";
        };

        awsProfileName = lib.mkOption {
          type = lib.types.str;
          default = name;
          description = ''
            Name of the AWS CLI profile to create in ~/.aws/config.
            Defaults to the attribute name in the profiles set.

            Must be unique across ALL identities (not just within one
            identity), because AWS CLI has a single flat profile
            namespace. Two identities both defining a profile named
            "admin" without overriding awsProfileName will collide and
            the module will refuse to evaluate.
          '';
          example = "my-profile";
        };

        makeDefault = lib.mkOption {
          type = lib.types.bool;
          default = false;
          description = ''
            If true, also configure the [default] profile with these
            settings. At most ONE profile across ALL identities may set
            this to true (AWS CLI only recognises one [default]).
          '';
        };

        sessionDuration = lib.mkOption {
          type = lib.types.nullOr lib.types.int;
          default = null;
          description = ''
            Session duration in seconds. Overrides the enclosing
            identity's sessionDuration when set.
          '';
          example = 3600;
        };

        output = lib.mkOption {
          type = lib.types.enum [
            "json"
            "yaml"
            "text"
            "table"
          ];
          default = "json";
          description = "Default output format for AWS CLI";
        };

        extraConfig = lib.mkOption {
          type = lib.types.attrsOf lib.types.str;
          default = { };
          description = "Additional configuration options for the AWS CLI profile";
          example = {
            cli_pager = "";
            retry_mode = "standard";
          };
        };
      };
    };

  # Identity submodule - one entry per (cert, trust anchor, account).
  # Holds everything that's shared across the profiles assuming roles
  # under that identity's trust anchor.
  identitySubmodule =
    { ... }:
    {
      options = {
        # ===================
        # CERTIFICATE SOURCE
        # ===================
        # A tagged union. `source` selects the variant; only that
        # variant's fields are read.
        #
        # This is a union rather than a set of optional flags because
        # aws_signing_helper treats --cert-selector as mutually
        # exclusive with both --certificate and --private-key, so the
        # argument sets are genuinely disjoint.
        #
        # For source = "files" the module stays secrets-manager
        # agnostic - paths can come from:
        #   - SOPS: config.sops.secrets."iam-ra/<identity>/cert".path
        #   - agenix: config.age.secrets.iam-ra-<identity>-cert.path
        #   - Static files: "/etc/ssl/iam-ra/<identity>/cert.pem"
        #   - iam-ra host enroll (v3): a host-generated key under
        #     $XDG_STATE_HOME/iam-ra/keys/<label>/
        certificate = {
          source = lib.mkOption {
            type = lib.types.enum [
              "files"
              "macosKeychain"
            ];
            default = "files";
            description = ''
              Where the identity's certificate and private key live.

              `files` (default)
                Read both from the filesystem. Set `certPath` and
                `keyPath`. The key is readable by anyone who can read
                the file.

              `macosKeychain`
                Use an identity already imported into a macOS keychain,
                selected with `selector`. The private key never leaves
                the keychain and can be marked non-extractable, so it
                cannot be copied off the host even by a process running
                as the owning user. Darwin only - the credential
                helper's certificate-store support is a hard error on
                Linux, so the module refuses to evaluate elsewhere.
                Requires the keychain to be unlocked and on the search
                list (`security list-keychains`).
            '';
            example = "macosKeychain";
          };

          certPath = lib.mkOption {
            type = lib.types.nullOr (lib.types.either lib.types.path lib.types.str);
            default = null;
            description = ''
              Path to the X.509 certificate file (PEM format).
              Required when `source = "files"`, ignored otherwise.

              This certificate identifies the host within this identity
              and is shared across all profiles in this identity.

              The certificate is not secret - it is presented in TLS
              handshakes - so it does not need a secrets manager and may
              be committed to your Nix configuration as a plain path.
            '';
            example = "/run/secrets/iam-ra/work/cert.pem";
          };

          keyPath = lib.mkOption {
            type = lib.types.nullOr (lib.types.either lib.types.path lib.types.str);
            default = null;
            description = ''
              Path to the private key file (PEM format).
              Required when `source = "files"`, ignored otherwise.

              This key corresponds to the certificate and is shared
              across all profiles in this identity.

              Note this must be a real, re-readable file. The credential
              helper re-opens the key on every operation, so a FIFO,
              process substitution or /dev/stdin will fail after the
              first read.
            '';
            example = "/run/secrets/iam-ra/work/key.pem";
          };

          selector = {
            subject = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
              description = ''
                Certificate subject to match in the keychain
                (`x509Subject`). Used when `source = "macosKeychain"`.

                Matching is exact, against the full distinguished name.
                A value of "CN=web01" therefore matches only a subject
                consisting of exactly that one RDN. At least one of
                `subject`, `issuer` or `serial` must be set.
              '';
              example = "CN=web01";
            };

            issuer = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
              description = ''
                Certificate issuer to match in the keychain
                (`x509Issuer`). Same exact full-DN matching as
                `subject`.
              '';
              example = "CN=IAM Roles Anywhere CA";
            };

            serial = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
              description = ''
                Certificate serial number to match in the keychain
                (`x509Serial`), interpreted as base 16.

                Pins one exact certificate, so it must be updated on
                every rotation - prefer `subject` unless you
                specifically need to disambiguate.
              '';
              example = "15D19632234BF759A32802C0DA88F9E8AFC8702D";
            };
          };
        };

        # ===================
        # AWS CONFIG (per-identity)
        # ===================
        trustAnchorArn = lib.mkOption {
          type = lib.types.str;
          description = ''
            ARN of the IAM Roles Anywhere trust anchor for this identity.
            The identity's certificate must have been issued by a CA the
            trust anchor trusts.
          '';
          example = "arn:aws:rolesanywhere:ap-southeast-2:123456789012:trust-anchor/abc123";
        };

        region = lib.mkOption {
          type = lib.types.str;
          description = ''
            AWS region for API calls for this identity's profiles.
            All profiles within this identity share the same region;
            cross-region access within a single AWS account requires
            either profile-specific ~/.aws/config overrides (via
            extraConfig) or separate identities.
          '';
          example = "ap-southeast-2";
        };

        sessionDuration = lib.mkOption {
          type = lib.types.nullOr lib.types.int;
          default = null;
          description = ''
            Default session duration in seconds for profiles in this
            identity. Individual profiles can override this via their
            own sessionDuration option.
          '';
          example = 3600;
        };

        # ===================
        # PROFILES (within this identity)
        # ===================
        profiles = lib.mkOption {
          type = lib.types.attrsOf (lib.types.submodule profileSubmodule);
          default = { };
          description = ''
            Named profiles for this identity. Each profile assumes a
            different IAM role using the identity's shared certificate.
            The attribute name is used as the AWS CLI profile name by
            default (overridable via awsProfileName).

            Profile names (after awsProfileName defaulting) must be
            unique across ALL identities - see module-validation.nix.

            Management via the CLI:
                iam-ra host onboard <host> --role X --role Y    # multi-role onboard
                iam-ra host add-role <host> <role>              # attach a role
                iam-ra host remove-role <host> <role>           # detach a role
                iam-ra host rotate-cert <host>                  # renew cert, keep roles
          '';
          example = lib.literalExpression ''
            {
              admin = {
                profileArn = "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/admin";
                roleArn = "arn:aws:iam::123456789012:role/admin";
                makeDefault = true;
              };
              readonly = {
                profileArn = "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/readonly";
                roleArn = "arn:aws:iam::123456789012:role/readonly";
              };
            }
          '';
        };
      };
    };
in
{
  enable = lib.mkEnableOption "IAM Roles Anywhere authentication";

  # ===================
  # CREDENTIAL PROCESS FORMAT
  # ===================
  # By default the AWS config entry contains a single-line
  # `credential_process` command running several hundred characters:
  # the aws_signing_helper nix-store path, all certificate paths, all
  # ARNs, region, duration. Setting this option to true replaces that
  # inline command with an absolute path to a per-profile shell
  # wrapper script at ~/.aws/iam-ra/<awsProfileName>.sh - far more
  # readable when inspecting ~/.aws/config or debugging, at the cost
  # of one extra file per profile under $HOME/.aws/iam-ra/.

  useCredentialProcessWrapper = lib.mkOption {
    type = lib.types.bool;
    default = false;
    description = ''
      If true, write each profile's credential_process command to a
      per-profile shell wrapper script at
      `~/.aws/iam-ra/<awsProfileName>.sh` and reference it from
      `~/.aws/config` by absolute path, instead of embedding the full
      command inline in the config file.

      Rationale: the inline form (default, false) produces very long
      `credential_process =` lines in `~/.aws/config` - the
      aws_signing_helper store path plus certificate paths plus several
      ARNs plus region/duration - which is hard to read or diff. With
      this flag enabled, `~/.aws/config` contains just an absolute
      path to a short shell script; the script itself is managed
      declaratively by home-manager (content is regenerated on every
      activation) and contains `exec` of the signing helper with all
      arguments single-quoted for safety.

      Defaults to false (inline) to preserve the existing behaviour;
      opt in when you want a cleaner `~/.aws/config`.
    '';
    example = true;
  };

  # ===================
  # IDENTITIES
  # ===================
  # One entry per (cert, trust anchor, AWS account). Most users have a
  # single identity named `default`. Multi-account users (e.g. work +
  # personal on one laptop) declare one identity per account.
  #
  # Each identity owns its own certificate, trust anchor, region,
  # default session duration, and set of profiles. Profiles within an
  # identity share the cert and trust anchor.
  #
  # At least one identity is required when the module is enabled;
  # validation fails otherwise.

  identities = lib.mkOption {
    type = lib.types.attrsOf (lib.types.submodule identitySubmodule);
    default = { };
    description = ''
      Attribute set of IAM Roles Anywhere identities.

      Each identity = one AWS account / one trust anchor / one cert,
      with any number of profiles assuming different roles within that
      account. Across identities, profiles MUST have unique
      awsProfileName values (they map to the single AWS CLI profile
      namespace in ~/.aws/config).

      Example single-identity (most common):
        identities.default = {
          certificate.certPath = config.sops.secrets."iam-ra/cert".path;
          certificate.keyPath  = config.sops.secrets."iam-ra/key".path;
          trustAnchorArn = "arn:aws:rolesanywhere:...";
          region = "ap-southeast-2";
          profiles.admin = { profileArn = "..."; roleArn = "..."; makeDefault = true; };
        };

      Example multi-identity (cross-account):
        identities = {
          work     = { ... trust anchor A, one cert, roles A1/A2 ... };
          personal = { ... trust anchor B, one cert, roles B1      ... };
        };
    '';
    example = lib.literalExpression ''
      {
        default = {
          certificate = {
            certPath = config.sops.secrets."iam-ra/cert".path;
            keyPath  = config.sops.secrets."iam-ra/key".path;
          };
          trustAnchorArn = "arn:aws:rolesanywhere:ap-southeast-2:123456789012:trust-anchor/abc";
          region = "ap-southeast-2";
          profiles = {
            admin = {
              profileArn = "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/admin";
              roleArn    = "arn:aws:iam::123456789012:role/admin";
              makeDefault = true;
            };
          };
        };
      }
    '';
  };
}
