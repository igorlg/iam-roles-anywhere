# IAM Roles Anywhere Tests
{
  inputs,
  system,
  self,
}:

let
  pkgs = inputs.nixpkgs.legacyPackages.${system};
  lib = inputs.nixpkgs.lib;

  # Sample ARNs for testing (not real)
  testArns = {
    trustAnchor = "arn:aws:rolesanywhere:ap-southeast-2:123456789012:trust-anchor/00000000-0000-0000-0000-000000000001";
    trustAnchorPersonal = "arn:aws:rolesanywhere:ap-southeast-2:987098549565:trust-anchor/00000000-0000-0000-0000-0000000000aa";
    profile = "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/00000000-0000-0000-0000-000000000002";
    profileAdmin = "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/00000000-0000-0000-0000-000000000003";
    profileReadonly = "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/00000000-0000-0000-0000-000000000004";
    profilePersonal = "arn:aws:rolesanywhere:ap-southeast-2:987098549565:profile/00000000-0000-0000-0000-0000000000bb";
    role = "arn:aws:iam::123456789012:role/test-host-rolesanywhere";
    roleAdmin = "arn:aws:iam::123456789012:role/admin";
    roleReadonly = "arn:aws:iam::123456789012:role/readonly";
    rolePersonal = "arn:aws:iam::987098549565:role/personal-admin";
  };

  # Helper to create test home-manager configurations.
  # Returns the full activationPackage - forcing its realisation forces
  # assertion evaluation, so these tests double as assertion checks for
  # the happy paths.
  mkTestHome =
    {
      extraConfig ? { },
    }:
    (inputs.home-manager.lib.homeManagerConfiguration {
      inherit pkgs;
      modules = [
        self.homeModules.default
        {
          home = {
            username = "testuser";
            homeDirectory = if pkgs.stdenv.isDarwin then "/Users/testuser" else "/home/testuser";
            stateVersion = "24.11";
          };
        }
        extraConfig
      ];
    }).activationPackage;

  # Helper to assert that a config FAILS to evaluate due to a module
  # assertion firing. Home-manager converts `config.assertions` with
  # any assertion=false into a `throw` via `throwAssertions`, which
  # fires when `.activationPackage` is forced. `builtins.tryEval`
  # catches that throw; `success = false` means an assertion fired.
  #
  # We intentionally don't grep the error message - tryEval doesn't
  # expose it, and the specific assertion that SHOULD fire is
  # documented next to each test invocation below. The implied
  # assertion identity is the one unique to the test's config shape
  # (e.g. empty identities -> "At least one identity" assertion).
  mkAssertionFailsTest =
    name: extraConfig:
    let
      hmAttempt = builtins.tryEval (
        (inputs.home-manager.lib.homeManagerConfiguration {
          inherit pkgs;
          modules = [
            self.homeModules.default
            {
              home = {
                username = "testuser";
                homeDirectory = if pkgs.stdenv.isDarwin then "/Users/testuser" else "/home/testuser";
                stateVersion = "24.11";
              };
            }
            extraConfig
          ];
        }).activationPackage
      );
    in
    pkgs.runCommand name { } (
      if !hmAttempt.success then
        ''
          echo "PASS: module eval failed as expected (assertion fired)"
          mkdir -p $out
          echo PASS > $out/result
        ''
      else
        ''
          echo "FAIL: expected eval to fail but it succeeded"
          exit 1
        ''
    );

  # ===================
  # Library Tests
  # ===================

  test-lib-loads = pkgs.runCommand "test-iam-ra-lib-loads" { } ''
    echo "Testing library loads..."
    ${
      if
        self.lib ? mkCredentialProcessCommand
        && self.lib ? isValidTrustAnchorArn
        && self.lib ? isValidProfileArn
        && self.lib ? isValidRoleArn
      then
        ''
          echo "Library has mkCredentialProcessCommand: yes"
          echo "Library has ARN validators: yes"
          echo "PASS: Library loads successfully"
        ''
      else
        ''
          echo "FAIL: Library missing expected attributes"
          exit 1
        ''
    }
    mkdir -p $out
    echo "PASS" > $out/result
  '';

  test-lib-validation = pkgs.runCommand "test-iam-ra-lib-validation" { } ''
    echo "Testing ARN validation functions..."
    ${
      let
        inherit (self.lib) isValidTrustAnchorArn isValidProfileArn isValidRoleArn;
        validTrustAnchor = isValidTrustAnchorArn testArns.trustAnchor;
        validProfile = isValidProfileArn testArns.profile;
        validRole = isValidRoleArn testArns.role;
        invalidArn = isValidTrustAnchorArn "not-an-arn";
      in
      if validTrustAnchor && validProfile && validRole && !invalidArn then
        ''
          echo "Trust anchor validation: PASS"
          echo "Profile validation: PASS"
          echo "Role validation: PASS"
          echo "Invalid ARN rejection: PASS"
          echo "PASS: All validation tests passed"
        ''
      else
        ''
          echo "FAIL: Validation functions not working correctly"
          echo "  validTrustAnchor: ${toString validTrustAnchor}"
          echo "  validProfile: ${toString validProfile}"
          echo "  validRole: ${toString validRole}"
          echo "  invalidArn rejected: ${toString (!invalidArn)}"
          exit 1
        ''
    }
    mkdir -p $out
    echo "PASS" > $out/result
  '';

  test-lib-credential-command = pkgs.runCommand "test-iam-ra-credential-command" { } ''
    echo "Testing credential command generation..."
    ${
      let
        cmd = self.lib.mkCredentialProcessCommand {
          signingHelperPath = "/nix/store/fake/bin/aws_signing_helper";
          certificatePath = "/run/secrets/cert.pem";
          privateKeyPath = "/run/secrets/key.pem";
          trustAnchorArn = testArns.trustAnchor;
          profileArn = testArns.profile;
          roleArn = testArns.role;
          region = "ap-southeast-2";
        };
        hasHelper = builtins.match ".*aws_signing_helper.*" cmd != null;
        hasCert = builtins.match ".*--certificate.*/run/secrets/cert.pem.*" cmd != null;
        hasKey = builtins.match ".*--private-key.*/run/secrets/key.pem.*" cmd != null;
        hasTrustAnchor = builtins.match ".*--trust-anchor-arn.*" cmd != null;
      in
      if hasHelper && hasCert && hasKey && hasTrustAnchor then
        ''
          echo "Generated command: ${cmd}"
          echo "PASS: Credential command generation works"
        ''
      else
        ''
          echo "FAIL: Credential command generation incorrect"
          echo "Generated: ${cmd}"
          exit 1
        ''
    }
    mkdir -p $out
    echo "PASS" > $out/result
  '';

  # Contract test for the credential_process wrapper script. The
  # script shape is part of the module's public contract (users may
  # `cat ~/.aws/iam-ra/<profile>.sh` when debugging); keep the matches
  # below strict enough to catch regressions like lost shebang / lost
  # quoting / missing exec.
  test-lib-credential-script = pkgs.runCommand "test-iam-ra-credential-script" { } ''
    echo "Testing credential wrapper script generation..."
    ${
      let
        # certificatePath intentionally contains a space so we can
        # assert lib.escapeShellArg quotes values that actually need
        # it. (Nixpkgs's escapeShellArg is optimised to skip quotes
        # for strings of only [alnum,._+:@%/-], so a plain path
        # wouldn't exercise the quoting path.)
        script = self.lib.mkCredentialProcessScript {
          signingHelperPath = "/nix/store/fake/bin/aws_signing_helper";
          certificatePath = "/tmp/has space/cert.pem";
          privateKeyPath = "/run/secrets/key.pem";
          trustAnchorArn = testArns.trustAnchor;
          profileArn = testArns.profile;
          roleArn = testArns.role;
          region = "ap-southeast-2";
          sessionDuration = 3600;
        };
        # Substring checks via lib.hasInfix - cleaner than regex for
        # multi-line content (Nix's builtins.match is POSIX ERE and
        # does not cross newlines reliably).
        has = sub: lib.hasInfix sub script;
        hasShebang = has "#!/usr/bin/env bash";
        hasExec = has "exec ";
        hasHelper = has "aws_signing_helper";
        hasCert = has "--certificate";
        hasKey = has "--private-key";
        hasKeyPath = has "/run/secrets/key.pem";
        hasTrustAnchor = has "--trust-anchor-arn";
        hasProfileArn = has "--profile-arn";
        hasRoleArn = has "--role-arn";
        hasRegion = has "--region";
        hasRegionValue = has "ap-southeast-2";
        hasDuration = has "--session-duration";
        hasDurationValue = has "3600";
        # Values with shell metacharacters (spaces here) MUST be
        # quoted by lib.escapeShellArg - otherwise the wrapper script
        # breaks when any real-world path contains special chars.
        hasQuotedCertPath = has "'/tmp/has space/cert.pem'";
      in
      if
        hasShebang
        && hasExec
        && hasHelper
        && hasCert
        && hasKey
        && hasKeyPath
        && hasTrustAnchor
        && hasProfileArn
        && hasRoleArn
        && hasRegion
        && hasRegionValue
        && hasDuration
        && hasDurationValue
        && hasQuotedCertPath
      then
        ''
          echo "PASS: Credential wrapper script generation works"
        ''
      else
        ''
          echo "FAIL: Credential wrapper script generation incorrect"
          echo "Generated script:"
          cat <<'SCRIPT_EOF'
          ${script}
          SCRIPT_EOF
          echo "hasShebang=${toString hasShebang}"
          echo "hasExec=${toString hasExec}"
          echo "hasHelper=${toString hasHelper}"
          echo "hasCert=${toString hasCert}"
          echo "hasKey=${toString hasKey}"
          echo "hasKeyPath=${toString hasKeyPath}"
          echo "hasTrustAnchor=${toString hasTrustAnchor}"
          echo "hasProfileArn=${toString hasProfileArn}"
          echo "hasRoleArn=${toString hasRoleArn}"
          echo "hasRegion=${toString hasRegion}"
          echo "hasRegionValue=${toString hasRegionValue}"
          echo "hasDuration=${toString hasDuration}"
          echo "hasDurationValue=${toString hasDurationValue}"
          echo "hasQuotedCertPath=${toString hasQuotedCertPath}"
          exit 1
        ''
    }
    mkdir -p $out
    echo "PASS" > $out/result
  '';

  # ===================
  # Module Existence Tests
  # ===================

  test-home-module-exists = pkgs.runCommand "test-iam-ra-home-module" { } ''
    echo "Testing home module exists..."
    ${
      if self ? homeModules && self.homeModules ? default then
        ''
          echo "PASS: Home module exists"
        ''
      else
        ''
          echo "FAIL: Home module missing"
          exit 1
        ''
    }
    mkdir -p $out
    echo "PASS" > $out/result
  '';

  test-nixos-module-exists = pkgs.runCommand "test-iam-ra-nixos-module" { } ''
    echo "Testing NixOS module exists..."
    ${
      if self ? nixosModules && self.nixosModules ? default then
        ''
          echo "PASS: NixOS module exists"
        ''
      else
        ''
          echo "FAIL: NixOS module missing"
          exit 1
        ''
    }
    mkdir -p $out
    echo "PASS" > $out/result
  '';

  test-darwin-module-exists = pkgs.runCommand "test-iam-ra-darwin-module" { } ''
    echo "Testing Darwin module exists..."
    ${
      if self ? darwinModules && self.darwinModules ? default then
        ''
          echo "PASS: Darwin module exists"
        ''
      else
        ''
          echo "FAIL: Darwin module missing"
          exit 1
        ''
    }
    mkdir -p $out
    echo "PASS" > $out/result
  '';

  # ===================
  # Home Module Config Tests (identities attrset - happy paths)
  # ===================

  # Module disabled by default
  test-home-disabled = mkTestHome {
    extraConfig = {
      # Module should be disabled by default
    };
  };

  # Single identity with one profile - the common case for a single-account host
  test-home-single-profile = mkTestHome {
    extraConfig = {
      programs.iamRolesAnywhere = {
        enable = true;
        identities.default = {
          trustAnchorArn = testArns.trustAnchor;
          region = "ap-southeast-2";
          certificate = {
            certPath = "/run/secrets/cert.pem";
            keyPath = "/run/secrets/key.pem";
          };
          profiles.default = {
            profileArn = testArns.profile;
            roleArn = testArns.role;
            makeDefault = true;
          };
        };
      };
    };
  };

  # Single identity with multiple profiles (scenario 2 - same cert, many roles)
  test-home-multi-profile = mkTestHome {
    extraConfig = {
      programs.iamRolesAnywhere = {
        enable = true;
        identities.default = {
          trustAnchorArn = testArns.trustAnchor;
          region = "ap-southeast-2";
          certificate = {
            certPath = "/run/secrets/cert.pem";
            keyPath = "/run/secrets/key.pem";
          };
          profiles = {
            admin = {
              profileArn = testArns.profileAdmin;
              roleArn = testArns.roleAdmin;
              makeDefault = true;
            };
            readonly = {
              profileArn = testArns.profileReadonly;
              roleArn = testArns.roleReadonly;
            };
          };
        };
      };
    };
  };

  # Full-options exercise, single identity
  test-home-multi-profile-custom = mkTestHome {
    extraConfig = {
      programs.iamRolesAnywhere = {
        enable = true;
        identities.default = {
          trustAnchorArn = testArns.trustAnchor;
          region = "us-east-1";
          sessionDuration = 3600;
          certificate = {
            certPath = "/custom/path/cert.pem";
            keyPath = "/custom/path/key.pem";
          };
          profiles = {
            admin = {
              profileArn = testArns.profileAdmin;
              roleArn = testArns.roleAdmin;
              makeDefault = true;
              output = "yaml";
              extraConfig = {
                cli_pager = "";
              };
            };
            readonly = {
              profileArn = testArns.profileReadonly;
              roleArn = testArns.roleReadonly;
              awsProfileName = "ro"; # Custom profile name
              sessionDuration = 900; # Override per-identity default
            };
            deploy = {
              profileArn = testArns.profile;
              roleArn = testArns.role;
              sessionDuration = 7200;
              output = "json";
            };
          };
        };
      };
    };
  };

  # Multi-identity: scenario 3. Two AWS accounts, two certs, two trust
  # anchors, three profiles in total. Exactly one makeDefault across
  # all identities.
  test-home-multi-identity = mkTestHome {
    extraConfig = {
      programs.iamRolesAnywhere = {
        enable = true;
        identities = {
          work = {
            trustAnchorArn = testArns.trustAnchor;
            region = "ap-southeast-2";
            certificate = {
              certPath = "/run/secrets/iam-ra/work/cert.pem";
              keyPath = "/run/secrets/iam-ra/work/key.pem";
            };
            profiles = {
              work-admin = {
                profileArn = testArns.profileAdmin;
                roleArn = testArns.roleAdmin;
                makeDefault = true;
              };
              work-readonly = {
                profileArn = testArns.profileReadonly;
                roleArn = testArns.roleReadonly;
              };
            };
          };
          personal = {
            trustAnchorArn = testArns.trustAnchorPersonal;
            region = "ap-southeast-2";
            certificate = {
              certPath = "/run/secrets/iam-ra/personal/cert.pem";
              keyPath = "/run/secrets/iam-ra/personal/key.pem";
            };
            profiles.personal-admin = {
              profileArn = testArns.profilePersonal;
              roleArn = testArns.rolePersonal;
            };
          };
        };
      };
    };
  };

  # Wrapper-scripts feature: when useCredentialProcessWrapper = true,
  # the module emits ~/.aws/iam-ra/<profile>.sh files and points
  # credential_process at the absolute path instead of embedding the
  # full command inline. This test exercises the single-identity path.
  test-home-wrapper-scripts = mkTestHome {
    extraConfig = {
      programs.iamRolesAnywhere = {
        enable = true;
        useCredentialProcessWrapper = true;
        identities.default = {
          trustAnchorArn = testArns.trustAnchor;
          region = "ap-southeast-2";
          certificate = {
            certPath = "/run/secrets/cert.pem";
            keyPath = "/run/secrets/key.pem";
          };
          profiles = {
            admin = {
              profileArn = testArns.profileAdmin;
              roleArn = testArns.roleAdmin;
              makeDefault = true;
            };
            readonly = {
              profileArn = testArns.profileReadonly;
              roleArn = testArns.roleReadonly;
            };
          };
        };
      };
    };
  };

  # Wrapper-scripts + multi-identity. Cross-account with wrapper on;
  # each profile across identities gets its own script file.
  test-home-wrapper-scripts-multi-identity = mkTestHome {
    extraConfig = {
      programs.iamRolesAnywhere = {
        enable = true;
        useCredentialProcessWrapper = true;
        identities = {
          work = {
            trustAnchorArn = testArns.trustAnchor;
            region = "ap-southeast-2";
            certificate = {
              certPath = "/run/secrets/iam-ra/work/cert.pem";
              keyPath = "/run/secrets/iam-ra/work/key.pem";
            };
            profiles.work-admin = {
              profileArn = testArns.profileAdmin;
              roleArn = testArns.roleAdmin;
              makeDefault = true;
            };
          };
          personal = {
            trustAnchorArn = testArns.trustAnchorPersonal;
            region = "ap-southeast-2";
            certificate = {
              certPath = "/run/secrets/iam-ra/personal/cert.pem";
              keyPath = "/run/secrets/iam-ra/personal/key.pem";
            };
            profiles.personal-admin = {
              profileArn = testArns.profilePersonal;
              roleArn = testArns.rolePersonal;
            };
          };
        };
      };
    };
  };

  # ===================
  # Negative Tests (assertion coverage)
  # ===================
  # These exercise module-validation.nix assertions by building configs
  # that SHOULD fail, and assert that evaluation throws. Each test has
  # a comment naming the specific assertion it's expected to trip -
  # when you add/rename an assertion, update both the validation file
  # AND the comment here, so future-you can tell which assertion is
  # under test.

  # Expected assertion:
  #   "At least one identity must be defined in 'identities' when the module is enabled"
  test-empty-identities-fails = mkAssertionFailsTest "test-iam-ra-empty-identities-fails" {
    programs.iamRolesAnywhere = {
      enable = true;
      identities = { };
    };
  };

  # Expected assertion:
  #   "awsProfileName must be unique across all identities"
  # Two identities, each with a `.profiles.admin` defaulting
  # awsProfileName to "admin" -> collision.
  test-duplicate-aws-profile-name-fails =
    mkAssertionFailsTest "test-iam-ra-duplicate-aws-profile-name-fails"
      {
        programs.iamRolesAnywhere = {
          enable = true;
          identities = {
            work = {
              trustAnchorArn = testArns.trustAnchor;
              region = "ap-southeast-2";
              certificate = {
                certPath = "/run/secrets/work/cert.pem";
                keyPath = "/run/secrets/work/key.pem";
              };
              profiles.admin = {
                profileArn = testArns.profileAdmin;
                roleArn = testArns.roleAdmin;
              };
            };
            personal = {
              trustAnchorArn = testArns.trustAnchorPersonal;
              region = "ap-southeast-2";
              certificate = {
                certPath = "/run/secrets/personal/cert.pem";
                keyPath = "/run/secrets/personal/key.pem";
              };
              profiles.admin = {
                profileArn = testArns.profilePersonal;
                roleArn = testArns.rolePersonal;
              };
            };
          };
        };
      };

  # Expected assertion:
  #   "Only one profile can have makeDefault = true across all identities"
  test-multiple-make-default-fails = mkAssertionFailsTest "test-iam-ra-multiple-make-default-fails" {
    programs.iamRolesAnywhere = {
      enable = true;
      identities = {
        work = {
          trustAnchorArn = testArns.trustAnchor;
          region = "ap-southeast-2";
          certificate = {
            certPath = "/run/secrets/work/cert.pem";
            keyPath = "/run/secrets/work/key.pem";
          };
          profiles.work-admin = {
            profileArn = testArns.profileAdmin;
            roleArn = testArns.roleAdmin;
            makeDefault = true;
          };
        };
        personal = {
          trustAnchorArn = testArns.trustAnchorPersonal;
          region = "ap-southeast-2";
          certificate = {
            certPath = "/run/secrets/personal/cert.pem";
            keyPath = "/run/secrets/personal/key.pem";
          };
          profiles.personal-admin = {
            profileArn = testArns.profilePersonal;
            roleArn = testArns.rolePersonal;
            makeDefault = true;
          };
        };
      };
    };
  };

in
{
  # Library tests
  iam-ra-lib-loads = test-lib-loads;
  iam-ra-lib-validation = test-lib-validation;
  iam-ra-lib-credential-command = test-lib-credential-command;
  iam-ra-lib-credential-script = test-lib-credential-script;

  # Module existence tests
  iam-ra-home-module-exists = test-home-module-exists;
  iam-ra-nixos-module-exists = test-nixos-module-exists;
  iam-ra-darwin-module-exists = test-darwin-module-exists;

  # Home module config tests (positive)
  iam-ra-home-disabled = test-home-disabled;
  iam-ra-home-single-profile = test-home-single-profile;
  iam-ra-home-multi-profile = test-home-multi-profile;
  iam-ra-home-multi-profile-custom = test-home-multi-profile-custom;
  iam-ra-home-multi-identity = test-home-multi-identity;
  iam-ra-home-wrapper-scripts = test-home-wrapper-scripts;
  iam-ra-home-wrapper-scripts-multi-identity = test-home-wrapper-scripts-multi-identity;

  # Validation assertion tests (negative - config SHOULD fail)
  iam-ra-empty-identities-fails = test-empty-identities-fails;
  iam-ra-duplicate-aws-profile-name-fails = test-duplicate-aws-profile-name-fails;
  iam-ra-multiple-make-default-fails = test-multiple-make-default-fails;
}
