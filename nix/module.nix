# IAM Roles Anywhere - Module Exports
#
# Orchestrates the module components and exports:
#   - homeModule: for direct home-manager use
#   - systemModule: for NixOS/Darwin system-level use (adds 'user' option)
#
# Architecture:
#   options.nix      → Option definitions (the API surface)
#   packages.nix     → Package installation
#   aws-profile.nix  → AWS CLI profile configuration
#   validation.nix   → ARN validation and warnings
#   default.nix      → This file (orchestration)
{ lib }:

let
  # Import option definitions
  optionDefs = import ./module-options.nix { inherit lib; };

  # ===================
  # HOME-MANAGER MODULE
  # ===================
  # For direct use in home-manager configurations.
  # Usage:
  #   programs.iamRolesAnywhere = {
  #     enable = true;
  #     certificate.certPath = "/path/to/cert.pem";
  #     ...
  #   };

  homeModule =
    {
      config,
      lib,
      pkgs,
      ...
    }:
    let
      cfg = config.programs.iamRolesAnywhere;
      iamRaLib = import ./lib.nix { inherit lib; };

      # Build the credential_process command
      credentialProcessCommand = iamRaLib.mkCredentialProcessCommand {
        signingHelperPath = "${pkgs.aws-signing-helper}/bin/aws_signing_helper";
        certificatePath = toString cfg.certificate.certPath;
        privateKeyPath = toString cfg.certificate.keyPath;
        trustAnchorArn = cfg.aws.trustAnchorArn;
        profileArn = cfg.aws.profileArn;
        roleArn = cfg.aws.roleArn;
        region = cfg.aws.region;
        sessionDuration = cfg.aws.sessionDuration;
      };

      # Import component modules
      packagesConfig = import ./module-packages.nix { inherit pkgs; };
      awsProfileConfig = import ./module-aws-profile.nix { inherit lib cfg credentialProcessCommand; };
      validationConfig = import ./module-validation.nix { inherit lib cfg iamRaLib; };
    in
    {
      options.programs.iamRolesAnywhere = optionDefs;

      config = lib.mkIf cfg.enable (
        lib.mkMerge [
          packagesConfig
          awsProfileConfig
          validationConfig
        ]
      );
    };

  # ===================
  # SYSTEM MODULE
  # ===================
  # For NixOS and Darwin system-level configurations.
  # Adds 'user' option and wires to home-manager.
  # Usage:
  #   programs.iamRolesAnywhere = {
  #     enable = true;
  #     user = "alice";
  #     certificate.certPath = config.sops.secrets."iam-ra/cert".path;
  #     ...
  #   };

  systemModule =
    {
      config,
      lib,
      pkgs,
      ...
    }:
    let
      cfg = config.programs.iamRolesAnywhere;
    in
    {
      options.programs.iamRolesAnywhere = optionDefs // {
        user = lib.mkOption {
          type = lib.types.str;
          description = "Username to configure IAM Roles Anywhere for";
          example = "alice";
        };
      };

      config = lib.mkIf cfg.enable {
        # Wire the home module to the specified user via home-manager
        home-manager.users.${cfg.user} = {
          imports = [ homeModule ];

          programs.iamRolesAnywhere = {
            enable = true;
            certificate = {
              inherit (cfg.certificate) certPath keyPath;
            };
            aws = {
              inherit (cfg.aws)
                region
                trustAnchorArn
                profileArn
                roleArn
                sessionDuration
                ;
            };
            awsProfile = {
              inherit (cfg.awsProfile)
                name
                makeDefault
                output
                extraConfig
                ;
            };
          };
        };

        # User existence assertion - works on both NixOS and Darwin
        assertions = [
          {
            assertion = config.users.users ? ${cfg.user};
            message = "programs.iamRolesAnywhere: User '${cfg.user}' must exist in users.users";
          }
        ];
      };
    };

in
{
  inherit homeModule systemModule;
}
