# IAM Roles Anywhere CLI - Nix Package
#
# Builds the Python CLI using uv2nix from pyproject.toml + uv.lock.
#
# Returns: { packages.${system}, devShellPackages.${system} }
{ inputs, supportedSystems }:
let
  inherit (inputs.nixpkgs) lib;
  forAllSystems = lib.genAttrs supportedSystems;

  # Load workspace from root pyproject.toml + uv.lock
  workspace = inputs.uv2nix.lib.workspace.loadWorkspace { workspaceRoot = ./..; };

  # Overlay for production builds (prefer wheels)
  overlay = workspace.mkPyprojectOverlay {
    sourcePreference = "wheel";
  };

  # Python package sets per system
  pythonSets = forAllSystems (
    system:
    let
      pkgs = inputs.nixpkgs.legacyPackages.${system};
      python = pkgs.python312;
    in
    (pkgs.callPackage inputs.pyproject-nix.build.packages {
      inherit python;
    }).overrideScope
      (
        lib.composeManyExtensions [
          inputs.pyproject-build-systems.overlays.wheel
          overlay
        ]
      )
  );
in
{
  packages = forAllSystems (
    system:
    let
      pkgs = inputs.nixpkgs.legacyPackages.${system};
      pythonSet = pythonSets.${system};
      inherit (pkgs.callPackages inputs.pyproject-nix.build.util { }) mkApplication;
    in
    {
      iam-ra-cli = mkApplication {
        venv = pythonSet.mkVirtualEnv "iam-ra-cli-env" workspace.deps.default;
        package = pythonSet.iam-ra-cli;
      };
    }
  );

  devShellPackages = forAllSystems (
    system:
    let
      pkgs = inputs.nixpkgs.legacyPackages.${system};
      pythonSet = pythonSets.${system};
      virtualenv = pythonSet.mkVirtualEnv "iam-ra-cli-dev-env" workspace.deps.all;
    in
    [
      virtualenv
      pkgs.uv
    ]
  );
}
