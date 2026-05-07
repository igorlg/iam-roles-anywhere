# IAM Roles Anywhere - Module Exports
#
# Orchestrates the module components and exports:
#   - homeModule: for direct home-manager use
#   - systemModule: for NixOS/Darwin system-level use (adds 'user' option)
#
# Architecture:
#   module-options.nix     → Option definitions (the API surface)
#   module-packages.nix    → Package installation
#   module-aws-profile.nix → AWS CLI profile configuration (multi-identity)
#   module-validation.nix  → ARN validation and warnings
#   module.nix             → This file (orchestration)
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
  #     identities.default = {
  #       certificate.certPath = "/path/to/cert.pem";
  #       certificate.keyPath  = "/path/to/key.pem";
  #       trustAnchorArn = "arn:aws:rolesanywhere:...";
  #       region = "ap-southeast-2";
  #       profiles = {
  #         admin = { profileArn = "..."; roleArn = "..."; };
  #       };
  #     };
  #   };
  #
  # Multi-identity (cross-account):
  #   programs.iamRolesAnywhere = {
  #     enable = true;
  #     identities = {
  #       work     = { certificate = {...}; trustAnchorArn = "..."; region = "..."; profiles = {...}; };
  #       personal = { certificate = {...}; trustAnchorArn = "..."; region = "..."; profiles = {...}; };
  #     };
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

      # Import component modules
      packagesConfig = import ./module-packages.nix { inherit pkgs; };
      awsProfileConfig = import ./module-aws-profile.nix {
        inherit
          lib
          cfg
          config
          pkgs
          ;
        inherit (iamRaLib) mkCredentialProcessCommand mkCredentialProcessScript;
      };
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
  #     identities.default = {
  #       certificate.certPath = config.sops.secrets."iam-ra/cert".path;
  #       certificate.keyPath  = config.sops.secrets."iam-ra/key".path;
  #       trustAnchorArn = "arn:aws:rolesanywhere:...";
  #       region = "ap-southeast-2";
  #       profiles = {
  #         admin    = { profileArn = "..."; roleArn = "..."; makeDefault = true; };
  #         readonly = { profileArn = "..."; roleArn = "..."; };
  #       };
  #     };
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
        # Wire the home module to the specified user via home-manager.
        # With identities as a single attrset the wiring is trivial - no
        # manual per-option unpacking required.
        home-manager.users.${cfg.user} = {
          imports = [ homeModule ];

          programs.iamRolesAnywhere = {
            enable = true;
            inherit (cfg) identities useCredentialProcessWrapper;
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
