# Python packaging using uv2nix
#
# Single source of truth: ../pyproject.toml + ../uv.lock
# This file provides the workspace, overlays, and pythonSets for building
# the iam-ra-cli package.
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

  # Load workspace from pyproject.toml + uv.lock
  workspace = uv2nix.lib.workspace.loadWorkspace { workspaceRoot = ./..; };

  # Overlay for production builds (prefer wheels)
  overlay = workspace.mkPyprojectOverlay {
    sourcePreference = "wheel";
  };

  # Overlay for editable development installs
  editableOverlay = workspace.mkEditablePyprojectOverlay {
    root = "$REPO_ROOT";
  };

  # Python package sets per system
  pythonSets = forAllSystems (
    system:
    let
      pkgs = nixpkgs.legacyPackages.${system};
      python = pkgs.python312;
    in
    (pkgs.callPackage pyproject-nix.build.packages {
      inherit python;
    }).overrideScope
      (
        lib.composeManyExtensions [
          pyproject-build-systems.overlays.wheel
          overlay
        ]
      )
  );
in
{
  inherit
    workspace
    overlay
    editableOverlay
    pythonSets
    ;
}
