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
    profile = "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/00000000-0000-0000-0000-000000000002";
    profileAdmin = "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/00000000-0000-0000-0000-000000000003";
    profileReadonly = "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/00000000-0000-0000-0000-000000000004";
    role = "arn:aws:iam::123456789012:role/test-host-rolesanywhere";
    roleAdmin = "arn:aws:iam::123456789012:role/admin";
    roleReadonly = "arn:aws:iam::123456789012:role/readonly";
  };

  # Helper to create test home-manager configurations
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
  # Home Module Config Tests
  # ===================

  # Module disabled by default
  test-home-disabled = mkTestHome {
    extraConfig = {
      # Module should be disabled by default
    };
  };

  # Single profile configuration
  test-home-single-profile = mkTestHome {
    extraConfig = {
      programs.iamRolesAnywhere = {
        enable = true;
        trustAnchorArn = testArns.trustAnchor;
        region = "ap-southeast-2";
        certificate = {
          certPath = "/run/secrets/cert.pem";
          keyPath = "/run/secrets/key.pem";
        };
        profiles = {
          default = {
            profileArn = testArns.profile;
            roleArn = testArns.role;
            makeDefault = true;
          };
        };
      };
    };
  };

  # Multi-profile configuration
  test-home-multi-profile = mkTestHome {
    extraConfig = {
      programs.iamRolesAnywhere = {
        enable = true;
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

  # Multi-profile with custom settings
  test-home-multi-profile-custom = mkTestHome {
    extraConfig = {
      programs.iamRolesAnywhere = {
        enable = true;
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
            sessionDuration = 900; # Override global
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

in
{
  # Library tests
  iam-ra-lib-loads = test-lib-loads;
  iam-ra-lib-validation = test-lib-validation;
  iam-ra-lib-credential-command = test-lib-credential-command;

  # Module existence tests
  iam-ra-home-module-exists = test-home-module-exists;
  iam-ra-nixos-module-exists = test-nixos-module-exists;
  iam-ra-darwin-module-exists = test-darwin-module-exists;

  # Home module config tests
  iam-ra-home-disabled = test-home-disabled;
  iam-ra-home-single-profile = test-home-single-profile;
  iam-ra-home-multi-profile = test-home-multi-profile;
  iam-ra-home-multi-profile-custom = test-home-multi-profile-custom;
}
