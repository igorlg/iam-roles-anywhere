# Justfile for IAM Roles Anywhere
#
# Common development tasks. Run `just` to see available commands.
# Requires: just (https://github.com/casey/just)

# Default recipe - show help
default:
    @just --list

# ===================
# DEVELOPMENT
# ===================

# Enter development shell
dev:
    nix develop

# Format all Nix files
fmt:
    nix fmt

# Check formatting without modifying
fmt-check:
    nix fmt -- --check .

# ===================
# TESTING
# ===================

# Run all Nix checks
check:
    nix flake check --print-build-logs

# Run checks for specific system (e.g., just check-system x86_64-linux)
check-system system:
    nix flake check --print-build-logs --system {{system}}

# ===================
# BUILDING
# ===================

# Build the CLI
build:
    nix build .#iam-ra-cli --print-build-logs

# Build and run CLI with args (e.g., just run -- --help)
run *args:
    nix run .#iam-ra-cli -- {{args}}

# ===================
# CLI DEVELOPMENT
# ===================

# Run CLI tests (via uv in iam-ra-cli directory)
cli-test:
    cd iam-ra-cli && uv run pytest

# Update CLI dependencies
cli-lock:
    cd iam-ra-cli && uv lock

# Sync CLI dependencies
cli-sync:
    cd iam-ra-cli && uv sync --all-extras

# ===================
# CLOUDFORMATION
# ===================

# Lint CloudFormation templates
cfn-lint:
    cfn-lint iam-ra-cli/iam_ra_cli/data/cloudformation/*.yaml

# ===================
# RELEASE
# ===================

# Update flake inputs
update:
    nix flake update

# Update specific input (e.g., just update-input nixpkgs)
update-input input:
    nix flake update {{input}}

# ===================
# CLEANUP
# ===================

# Remove build artifacts
clean:
    rm -rf result
    rm -rf iam-ra-cli/.venv
    rm -rf iam-ra-cli/*.egg-info

# Garbage collect Nix store
gc:
    nix-collect-garbage -d
