{
  description = "IAM Roles Anywhere - Certificate-based AWS authentication for Nix hosts";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    home-manager = {
      url = "github:nix-community/home-manager";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    # Python packaging (uv2nix)
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
    { self, ... }@inputs:
    let
      inherit (inputs.nixpkgs) lib;

      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      forAllSystems = lib.genAttrs supportedSystems;

      # Import CLI package - returns { packages.${system}, devShellPackages.${system} }
      cli = import ./nix/package.nix { inherit inputs supportedSystems; };

      # Import module definitions
      modules = import ./nix/module.nix { inherit lib; };
    in
    {
      # ===== LIBRARY =====
      lib = import ./nix/lib.nix { inherit lib; };

      # ===== MODULES =====
      homeModules.default = modules.homeModule;
      nixosModules.default = modules.systemModule;
      darwinModules.default = modules.systemModule;

      # ===== PACKAGES =====
      packages = forAllSystems (system: {
        inherit (cli.packages.${system}) iam-ra-cli;
        default = cli.packages.${system}.iam-ra-cli;
      });

      # ===== DEV SHELLS =====
      devShells = import ./shells.nix {
        inherit inputs supportedSystems cli;
      };

      # ===== CHECKS =====
      checks = forAllSystems (
        system:
        import ./nix/checks.nix {
          inherit inputs system self;
        }
      );

      # ===== FORMATTER =====
      formatter = forAllSystems (system: inputs.nixpkgs.legacyPackages.${system}.nixfmt-rfc-style);
    };
}
