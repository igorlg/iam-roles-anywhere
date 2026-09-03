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
    nix fmt -- $(git ls-files '*.nix')

# Check formatting without modifying
fmt-check:
    nix fmt -- --check $(git ls-files '*.nix')

# ===================
# TESTING
# ===================

# Run all Nix checks
check:
    nix flake check --print-build-logs

# Run Python tests
test:
    uv run pytest tests/ -v
    uv run mypy src/iam_ra_cli
    uv run ruff check src/iam_ra_cli

# Run Python tests with coverage
test-cov:
    uv run pytest tests/ -v --cov=src/iam_ra_cli --cov-report=term-missing

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

# Sync CLI dependencies
sync:
    uv sync --all-extras

# Update CLI dependencies
lock:
    uv lock

# ===================
# CLOUDFORMATION
# ===================

# Lint CloudFormation templates
cfn-lint:
    uv run cfn-lint src/iam_ra_cli/data/cloudformation/*.yaml

# ===================
# DOCS
# ===================

# Lint Markdown against .markdownlint.json
md-lint:
    nix run nixpkgs#markdownlint-cli -- $(git ls-files '*.md')

# Fix auto-fixable Markdown issues
md-fix:
    nix run nixpkgs#markdownlint-cli -- --fix $(git ls-files '*.md')

# ===================
# VERSIONING
# ===================

# Check if all versions are in sync
version-check:
    ./scripts/sync-version.py --check

# Sync VERSION to all files
version-sync:
    ./scripts/sync-version.py

# Set new version and sync (e.g., just version 0.2.0)
version ver:
    ./scripts/sync-version.py {{ver}}

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
    find . -type d -name __pycache__ -exec rm -rf {} \; 2>/dev/null
    rm -rf result dist .venv .mypy_cache .pytest_cache .ruff_cache
    rm -rf *.egg-info
    rm -rf src/*.egg-info

# Garbage collect Nix store
gc:
    nix-collect-garbage -d
