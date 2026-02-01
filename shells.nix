# Development shells for IAM Roles Anywhere flake
#
# Provides a development environment with:
# - Python virtualenv (editable install from pyproject.toml + uv.lock)
# - uv for managing Python dependencies
# - Nix formatting/linting tools
# - AWS CLI and tools
# - Certificate management tools
# - just for task running
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

        # Task runner
        pkgs.just

        # Nix tools
        pkgs.nixfmt
        pkgs.statix
        pkgs.deadnix

        # AWS tools
        pkgs.awscli2
        pkgs.aws-signing-helper
        pkgs.aws-sam-cli

        # CloudFormation linting
        pkgs.cfn-lint

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
        echo "Run 'just' to see available commands"
        echo ""
      '';
    };
  }
)
