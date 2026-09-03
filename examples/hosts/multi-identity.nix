# Multi-Identity Configuration (scenario 3)
#
# A single laptop that needs to assume roles in MULTIPLE AWS accounts -
# e.g. a `work` account and a `personal` account. Each account has its
# own trust anchor, its own certificate, and its own set of profiles.
#
# Two identities = two certificates = two key pairs. Each is enrolled by
# running `iam-ra host enroll` under different AWS credentials
# (AWS_PROFILE=work, AWS_PROFILE=personal), in different `iam-ra`
# namespaces (--namespace work, --namespace personal).
#
# Both keys are generated on this laptop and neither leaves it, so there
# is nothing to transport and no secrets manager to configure.
#
# Prerequisites (run ONCE per account, with matching AWS credentials):
#
#   # Work account
#   AWS_PROFILE=work iam-ra init --namespace work
#   AWS_PROFILE=work iam-ra role create admin    --namespace work --policy arn:aws:iam::aws:policy/AdministratorAccess
#   AWS_PROFILE=work iam-ra role create readonly --namespace work --policy arn:aws:iam::aws:policy/ReadOnlyAccess
#   AWS_PROFILE=work iam-ra host enroll laptop --namespace work --role admin,readonly
#
#   # Personal account
#   AWS_PROFILE=personal iam-ra init --namespace personal
#   AWS_PROFILE=personal iam-ra role create personal-admin --namespace personal --policy arn:aws:iam::aws:policy/AdministratorAccess
#   AWS_PROFILE=personal iam-ra host enroll laptop --namespace personal --role personal-admin
#
# The key store keys off namespace + scope, so the two identities land in
# separate directories and cannot collide:
#   ~/.local/state/iam-ra/keys/work-default/
#   ~/.local/state/iam-ra/keys/personal-default/
#
{ ... }:
{
  programs.iamRolesAnywhere = {
    enable = true;
    user = "alice";

    identities = {
      # ==========
      # Work account (account ID 718758479978)
      # ==========
      work = {
        certificate = {
          source = "files";
          certPath = "/home/alice/.local/state/iam-ra/keys/work-default/cert.pem";
          keyPath = "/home/alice/.local/state/iam-ra/keys/work-default/key.pem";
        };

        trustAnchorArn = "arn:aws:rolesanywhere:ap-southeast-2:718758479978:trust-anchor/work-anchor";
        region = "ap-southeast-2";

        profiles = {
          work-admin = {
            profileArn = "arn:aws:rolesanywhere:ap-southeast-2:718758479978:profile/admin";
            roleArn = "arn:aws:iam::718758479978:role/iam-ra-admin";
            sessionDuration = 900; # shorter for admin
          };
          work-readonly = {
            profileArn = "arn:aws:rolesanywhere:ap-southeast-2:718758479978:profile/readonly";
            roleArn = "arn:aws:iam::718758479978:role/iam-ra-readonly";
            makeDefault = true; # safest default across the whole config
          };
        };
      };

      # ==========
      # Personal account (account ID 987098549565)
      # ==========
      personal = {
        certificate = {
          source = "files";
          certPath = "/home/alice/.local/state/iam-ra/keys/personal-default/cert.pem";
          keyPath = "/home/alice/.local/state/iam-ra/keys/personal-default/key.pem";
        };

        trustAnchorArn = "arn:aws:rolesanywhere:ap-southeast-2:987098549565:trust-anchor/personal-anchor";
        region = "ap-southeast-2";

        profiles.personal-admin = {
          profileArn = "arn:aws:rolesanywhere:ap-southeast-2:987098549565:profile/personal-admin";
          roleArn = "arn:aws:iam::987098549565:role/iam-ra-personal-admin";
          # No makeDefault - at most one profile across ALL identities
          # can be default; we picked work-readonly above.
        };
      };
    };
  };
}

# Generated ~/.aws/config will have:
#   [default]                     (= work-readonly)
#   [profile work-admin]
#   [profile work-readonly]
#   [profile personal-admin]
#
# Each profile's credential_process uses its identity's cert + trust
# anchor, so switching between accounts is just a matter of AWS_PROFILE:
#
#   aws sts get-caller-identity                        # work-readonly (default)
#   aws sts get-caller-identity --profile work-admin
#   aws sts get-caller-identity --profile personal-admin
#
# Key constraints the module enforces:
#   - Profile names (after awsProfileName defaulting) are globally
#     unique. "admin" in both identities would collide - use
#     "work-admin" / "personal-admin", or set awsProfileName explicitly.
#   - At most ONE profile (across ALL identities) may set makeDefault.
