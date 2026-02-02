# IAM Roles Anywhere CLI - Package export
#
# Builds the iam-ra-cli package from pyproject.toml + uv.lock using uv2nix.
# Usage in flake.nix:
#   packages = iamRaCli.packages;
{
  lib,
  nixpkgs,
  pyproject-nix,
  uv2nix,
  pyproject-build-systems,
  supportedSystems,
}:
let
  forAllSystems = lib.genAttrs supportedSystems;

  python = import ./python.nix {
    inherit
      lib
      nixpkgs
      pyproject-nix
      uv2nix
      pyproject-build-systems
      supportedSystems
      ;
  };

  inherit (python) workspace pythonSets editableOverlay;
in
{
  # Re-export python internals for shells.nix
  inherit python;

  # Package outputs
  packages = forAllSystems (
    system:
    let
      pkgs = nixpkgs.legacyPackages.${system};
      pythonSet = pythonSets.${system};
      inherit (pkgs.callPackages pyproject-nix.build.util { }) mkApplication;
    in
    {
      iam-ra-cli = mkApplication {
        venv = pythonSet.mkVirtualEnv "iam-ra-cli-env" workspace.deps.default;
        package = pythonSet.iam-ra-cli;
      };

      default = mkApplication {
        venv = pythonSet.mkVirtualEnv "iam-ra-cli-env" workspace.deps.default;
        package = pythonSet.iam-ra-cli;
      };
    }
  );
}
