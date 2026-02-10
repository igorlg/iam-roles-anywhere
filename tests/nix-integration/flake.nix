# Test flake simulating a consumer importing iam-roles-anywhere
#
# This tests both use cases:
# 1. Installing iam-ra-cli as a package
# 2. Using the home-manager module to configure a host
{
  description = "Test consumer of iam-roles-anywhere flake";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    home-manager = {
      url = "github:nix-community/home-manager";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    # Import the local iam-roles-anywhere flake
    iam-ra.url = "path:../..";
  };

  outputs = { self, nixpkgs, home-manager, iam-ra }:
    let
      system = "aarch64-darwin";
      pkgs = nixpkgs.legacyPackages.${system};

      # Test ARNs (fake but valid format)
      testArns = {
        trustAnchor = "arn:aws:rolesanywhere:ap-southeast-2:123456789012:trust-anchor/00000000-0000-0000-0000-000000000001";
        profile = "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/00000000-0000-0000-0000-000000000002";
        role = "arn:aws:iam::123456789012:role/test-rolesanywhere";
      };

      # ========================================
      # TEST 1: Package installation
      # ========================================
      # Consumer can add iam-ra-cli to their packages
      test-cli-available = pkgs.runCommand "test-cli-available" {} ''
        echo "Testing that iam-ra-cli package is available..."
        test -x "${iam-ra.packages.${system}.iam-ra-cli}/bin/iam-ra"
        echo "PASS: iam-ra-cli binary exists"
        mkdir -p $out
        echo "PASS" > $out/result
      '';

      # ========================================
      # TEST 2: Home-manager module works
      # ========================================
      # Consumer can use homeModules.default to configure a host
      test-home-module = (home-manager.lib.homeManagerConfiguration {
        inherit pkgs;
        modules = [
          # Import the iam-ra home module
          iam-ra.homeModules.default
          
          # Configure the module
          {
            home = {
              username = "testuser";
              homeDirectory = "/Users/testuser";
              stateVersion = "24.11";
            };

            programs.iamRolesAnywhere = {
              enable = true;
              certificate = {
                certPath = "/run/secrets/iam-ra/cert.pem";
                keyPath = "/run/secrets/iam-ra/key.pem";
              };
              aws = {
                region = "ap-southeast-2";
                trustAnchorArn = testArns.trustAnchor;
                profileArn = testArns.profile;
                roleArn = testArns.role;
              };
              awsProfile = {
                name = "iam-ra";
                makeDefault = false;
              };
            };
          }
        ];
      }).activationPackage;

      # ========================================
      # TEST 3: Library functions accessible
      # ========================================
      test-lib-accessible = pkgs.runCommand "test-lib-accessible" {} ''
        echo "Testing that lib functions are accessible..."
        ${
          let
            cmd = iam-ra.lib.mkCredentialProcessCommand {
              signingHelperPath = "/nix/store/fake/aws_signing_helper";
              certificatePath = "/path/to/cert.pem";
              privateKeyPath = "/path/to/key.pem";
              trustAnchorArn = testArns.trustAnchor;
              profileArn = testArns.profile;
              roleArn = testArns.role;
            };
            valid = iam-ra.lib.isValidTrustAnchorArn testArns.trustAnchor;
          in
          if valid && builtins.isString cmd then
            ''
              echo "mkCredentialProcessCommand works"
              echo "isValidTrustAnchorArn works"
              echo "PASS: Library functions accessible"
            ''
          else
            ''
              echo "FAIL: Library functions not working"
              exit 1
            ''
        }
        mkdir -p $out
        echo "PASS" > $out/result
      '';

    in
    {
      packages.${system} = {
        inherit test-cli-available test-home-module test-lib-accessible;
      };

      checks.${system} = {
        cli-available = test-cli-available;
        home-module = test-home-module;
        lib-accessible = test-lib-accessible;
      };
    };
}
