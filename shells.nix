# Development shells for IAM Roles Anywhere flake
#
# Provides a development environment with:
# - Python virtualenv (editable install from pyproject.toml + uv.lock)
# - uv for managing Python dependencies
# - Nix formatting/linting tools
# - AWS CLI and tools
# - Certificate management tools
{
  lib,
  nixpkgs,
  iamRaCli,
  supportedSystems,
}:
let
  forAllSystems = lib.genAttrs supportedSystems;

  inherit (iamRaCli.python) workspace pythonSets editableOverlay;
in
forAllSystems (
  system:
  let
    pkgs = nixpkgs.legacyPackages.${system};
    pythonSet = pythonSets.${system}.overrideScope editableOverlay;
    virtualenv = pythonSet.mkVirtualEnv "iam-ra-cli-dev-env" workspace.deps.all;
  in
  {
    default = pkgs.mkShell {
      packages = [
        virtualenv
        pkgs.uv

        # Nix tools
        pkgs.nixfmt
        pkgs.statix
        pkgs.deadnix

        # AWS tools
        pkgs.awscli2
        pkgs.aws-signing-helper
        pkgs.aws-sam-cli

        # Certificate tools
        pkgs.openssl

        # SOPS for secrets
        pkgs.sops
      ];

      env = {
        # Prevent uv from managing virtualenv - Nix handles this
        UV_NO_SYNC = "1";
        UV_PYTHON = pythonSet.python.interpreter;
        UV_PYTHON_DOWNLOADS = "never";
      };

      shellHook = ''
        unset PYTHONPATH
        export REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)

        echo "IAM Roles Anywhere development shell"
        echo ""
        echo "Python deps from: iam-ra-cli/pyproject.toml + uv.lock"
        echo ""
        echo "Structure:"
        echo "  modules/credentials.nix  - Core home-manager module"
        echo "  modules/nixos.nix        - NixOS wrapper"
        echo "  iam-ra-cli/              - Python CLI (deps from pyproject.toml)"
        echo "  cloudformation/          - SAM templates"
        echo ""
        echo "Commands:"
        echo "  uv add <package>         - Add Python dependency"
        echo "  uv lock                  - Update uv.lock"
        echo "  iam-ra --help            - CLI usage"
        echo ""
      '';
    };
  }
)
