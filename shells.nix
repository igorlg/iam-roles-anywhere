# Development Shell
#
# Combines dev dependencies from CLI and CDK packages with shared tooling.
#
# Usage: nix develop
{ inputs, supportedSystems, cli, cdk }:
let
  inherit (inputs.nixpkgs) lib;
  forAllSystems = lib.genAttrs supportedSystems;
in
forAllSystems (
  system:
  let
    pkgs = inputs.nixpkgs.legacyPackages.${system};
  in
  {
    default = pkgs.mkShell {
      packages =
        # Package-specific dev dependencies
        cli.devShellPackages.${system}
        ++ cdk.devShellPackages.${system}
        ++ [
          # Task runner
          pkgs.just

          # Nix tools
          pkgs.nixfmt
          pkgs.statix
          pkgs.deadnix

          # AWS tools
          pkgs.awscli2
          pkgs.aws-signing-helper

          # Certificate tools
          pkgs.openssl

          # SOPS for secrets
          pkgs.sops
        ];

      env = {
        # Prevent uv from downloading Python - use Nix-provided
        UV_PYTHON_DOWNLOADS = "never";
      };

      shellHook = ''
        echo "IAM Roles Anywhere development shell"
        echo ""
        echo "Available tools:"
        echo "  iam-ra    - CLI for IAM Roles Anywhere"
        echo "  cdk       - AWS CDK CLI"
        echo "  aws       - AWS CLI"
        echo "  just      - Task runner"
        echo ""
        echo "For Python development with hot-reload:"
        echo "  uv sync && source .venv/bin/activate"
        echo ""
        echo "Run 'just' to see available commands"
      '';
    };
  }
)
