{
  description = "IAM Roles Anywhere - Certificate-based AWS authentication for Nix hosts";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    home-manager = {
      url = "github:nix-community/home-manager";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    # Python packaging - single source of truth from pyproject.toml + uv.lock
    pyproject-nix = {
      url = "github:pyproject-nix/pyproject.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    uv2nix = {
      url = "github:pyproject-nix/uv2nix";
      inputs.pyproject-nix.follows = "pyproject-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    pyproject-build-systems = {
      url = "github:pyproject-nix/build-system-pkgs";
      inputs.pyproject-nix.follows = "pyproject-nix";
      inputs.uv2nix.follows = "uv2nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      home-manager,
      pyproject-nix,
      uv2nix,
      pyproject-build-systems,
      ...
    }:
    let
      inherit (nixpkgs) lib;

      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      # IAM RA CLI package (Python, built with uv2nix)
      iamRaCli = import ./iam-ra-cli/nix {
        inherit
          lib
          nixpkgs
          pyproject-nix
          uv2nix
          pyproject-build-systems
          supportedSystems
          ;
      };

      # Import module definitions
      modules = import ./modules { inherit lib; };
    in
    {
      # ===================
      # LIBRARY FUNCTIONS
      # ===================

      lib = import ./lib { inherit lib; };

      # ===================
      # MODULES
      # ===================

      # Home-manager module - for direct use in home-manager configurations
      # Usage: programs.iamRolesAnywhere = { enable = true; ... };
      homeModules.default = modules.homeModule;

      # NixOS module - adds 'user' option and wires to home-manager
      # Usage: programs.iamRolesAnywhere = { enable = true; user = "alice"; ... };
      nixosModules.default = modules.systemModule;

      # Darwin module - same as NixOS, works on macOS with nix-darwin
      darwinModules.default = modules.systemModule;

      # ===================
      # PACKAGES
      # ===================

      packages = iamRaCli.packages;

      # ===================
      # TESTS
      # ===================

      checks = lib.genAttrs supportedSystems (
        system:
        import ./tests {
          inherit
            self
            nixpkgs
            home-manager
            system
            ;
        }
      );

      # ===================
      # DEV SHELL
      # ===================

      devShells = import ./shells.nix {
        inherit
          lib
          nixpkgs
          iamRaCli
          supportedSystems
          ;
      };

      # ===================
      # FORMATTER
      # ===================

      formatter = lib.genAttrs supportedSystems (system: nixpkgs.legacyPackages.${system}.nixfmt);
    };
}
