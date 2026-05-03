# Plan: CI Workflow Architecture Refactor

Status: Agreed, ready to implement

## Context

The project currently has 4 workflow files and exhibits three related issues that compound over time:

1. **Over-triggering**: `ci.yaml` has no `paths:` filter, so a docs-only commit runs full Nix builds across 2 architectures.
2. **Redundant work**: `ci.yaml` and `cli.yaml` both run `nix build .#iam-ra-cli`. A Python source change triggers this build 3 times (x86_64, aarch64 in `ci.yaml` + ubuntu-latest in `cli.yaml`).
3. **Missing coverage**: nothing validates docs. Broken links, typos, markdown inconsistencies ship to users.

This plan proposes a restructure to fix all three.

## Goals

- Every job runs only when its outputs are affected by the change.
- Each workflow has a single, obvious concern (readable `paths:` filter).
- No build is duplicated across workflows.
- Docs get first-class validation: links, style, typos.

## Non-goals

- Artifact caching/reuse between workflows (complex; marginal gain).
- Eliminating the post-release `verify-build` step (see "Build count" below).

## Current state

| Workflow | Jobs | Path filter | Runs on |
|---|---|---|---|
| `ci.yaml` | Nix Check (x2 archs), Build (x2 archs), Format Check | **none** (runs on every push) | push to non-main |
| `cli.yaml` | Python Tests, Nix Build | `src/**`, `tests/**`, `pyproject.toml`, `uv.lock`, workflow self | push to non-main |
| `cloudformation.yaml` | Validate Templates | `src/iam_ra_cli/data/cloudformation/**`, `pyproject.toml`, `uv.lock`, workflow self | push to non-main |
| `release.yaml` | Check Version Label, Create Release, Verify Build | none (intentional) | PRs + push to main |

### Problems concretely

A **docs-only change** (`README.md`) currently triggers:

- `ci.yaml`: Nix Check x2, Build x2, Format Check = **5 jobs**

A **`src/**/*.py` change** currently triggers:

- `ci.yaml`: Nix Check x2, Build x2, Format Check = 5 jobs
- `cli.yaml`: Python Tests + Nix Build = 2 jobs
- Total: **7 jobs**, with 3 redundant Nix builds.

A **`.nix` or `flake.lock` change** currently triggers:

- `ci.yaml`: full 5 jobs
- `cli.yaml`: doesn't trigger (paths don't match) — even though Nix changes affect the package build.

## Proposed architecture

### Workflow split

| Workflow | Jobs | Triggers |
|---|---|---|
| `nix.yaml` | `check` (flake check, x2 archs), `build` (nix build + run, x2 archs), `format` (nixfmt) | `**/*.nix`, `flake.lock`, `flake.nix`, `shells.nix`, `src/**`, `pyproject.toml`, `uv.lock`, `.python-version`, `VERSION`, `examples/**`, workflow self |
| `python.yaml` | `test` (pytest + mypy + ruff + CLI smoke) | `src/**`, `tests/**`, `pyproject.toml`, `uv.lock`, `.python-version`, workflow self |
| `cloudformation.yaml` | `validate` (cfn-lint) | `src/iam_ra_cli/data/cloudformation/**`, `pyproject.toml`, `uv.lock`, workflow self |
| `docs.yaml` (new) | `markdown` (markdownlint), `links` (lychee, internal strict + external warn), `spell` (codespell on docs) | `**/*.md`, `docs/**`, `README.md`, `examples/**/*.md`, workflow self |
| `release.yaml` | unchanged | unchanged |

### Rename rationale

- `ci.yaml` → `nix.yaml`: name now matches its actual concern.
- `cli.yaml` → `python.yaml`: drops the redundant `nix-build` job; name reflects what it tests.

### Path filter triggers after refactor

A **docs-only change**:

- `docs.yaml`: markdown + links + spell = **3 jobs**
- Nothing else triggers.
- Savings: -5 Nix jobs previously run for no reason.

A **`src/**/*.py` change**:

- `nix.yaml`: check x2, build x2, format = 5 jobs (src/** matches)
- `python.yaml`: test = 1 job
- Total: **6 jobs** (down from 7; eliminated duplicate Nix build).

A **`.nix` or `flake.lock` change**:

- `nix.yaml`: 5 jobs
- Nothing else triggers.
- **New coverage**: previously `flake.lock` changes didn't trigger `cli.yaml`'s nix-build.

A **CFN-only change**:

- `cloudformation.yaml`: validate
- `nix.yaml`: check + build (since `src/**` matches CFN paths)
- Acceptable — CFN templates are embedded in the Nix package, so validating the build still makes sense.

## Docs workflow design

### Tooling

| Tool | Concern | Mode |
|---|---|---|
| **markdownlint-cli2** | Heading consistency, trailing whitespace, broken lists, style | **Block** |
| **lychee** | Link checking — internal anchors + paths, external URLs | **Block** for internal (`--exclude-all-private`, `--no-progress`); **warn** for external (separate job with `continue-on-error: true`) |
| **codespell** | Common misspellings in docs | **Block**, scoped to `*.md`, `docs/**` |

### Configuration files

- `.markdownlint.json` at repo root — start with defaults, adjust rules as needed (likely disable MD013 line-length).
- `.lychee.toml` at repo root — configure skips for known-auth-walled URLs, retry policy.
- `.codespellrc` at repo root — ignore list for project-specific jargon (e.g. `iam`, `ra`, `hostnames`).

### Strictness decision

Per earlier discussion: block style + internal links; warn external. Rationale:

- Internal link breakage = we introduced it, always fixable.
- External link breakage = could be temporary (their server's down), network flakiness. Warning keeps the PR unblocked.

External checks run as a separate job with `continue-on-error: true` so CI shows them but doesn't fail PRs.

## Build count: decision

**Keep both PR-time build and `verify-build`**.

Rationale:

- PR build validates the code as written.
- `verify-build` validates the *version-bump commit* the release workflow itself creates (sync-version.py ran + uv.lock regenerated + commit pushed).
- After [#20](https://github.com/igorlg/iam-roles-anywhere/pull/20), `sync-version.py --check` already catches most bump-induced breakage pre-push, but `verify-build` remains the last line of defence for "the Nix package itself fails to build after the bump". Rare, but the cost is one cached-friendly build on ubuntu-latest.
- Artifact reuse between PR and verify-build is not pursued: merge commits break SHA-based cache keys, and magic-nix-cache already deduplicates most of the work.

After removing the redundant `cli.yaml` nix-build: a Python change triggers 2 builds (ci x2 archs + post-release verify). That's the floor without complex cache-key engineering.

## Release-skip for docs PRs

The `skip-release` label on the `release.yaml` workflow already handles docs-only PRs: the release job short-circuits, no version bump, no tag. No changes needed. Document in contributor guide (follow-up).

## Implementation plan

Broken into small, independently reviewable commits:

1. **Rename and split**: `ci.yaml` → `nix.yaml`, `cli.yaml` → `python.yaml`; remove redundant `nix-build` from `python.yaml`.
2. **Tighten paths**: add full path filters to `nix.yaml` and `python.yaml`.
3. **Docs workflow**: new `docs.yaml` + config files (`.markdownlint.json`, `.lychee.toml`, `.codespellrc`).
4. **Verify with dummy PRs**: docs-only, src-only, nix-only, cfn-only — ensure only the expected workflows trigger.

Single PR, labelled `patch` (pure infra change, no behaviour change for users of the CLI).

## Open questions

All resolved:

1. **Branch protection rules**: the project has none today. Recommendation for when/if added: use GitHub's "required only if run" setting for `nix.yaml` and `python.yaml` so docs-only PRs (which don't trigger them) aren't blocked. Not a blocker for this PR; just a note for future.
2. **Existing `docs/` files** (`KUBERNETES.md`, `cli-design.md`): any issues flagged by markdownlint/lychee/codespell get fixed as part of this PR. No baseline-ignore.
3. **codespell on code**: not pursued. Docs-only scope.

## Costs

- One-time: markdownlint/lychee/codespell may flag pre-existing issues. Time cost to clean up.
- Ongoing: -1 redundant Nix build per Python push; +3 fast doc jobs per docs push.
- Net: CI time **decreases** for code changes (most common), adds ~30s to docs changes (which currently have zero validation).

## Alternatives considered

- **Single mega-workflow with `dorny/paths-filter`**: one file, per-job guards. Rejected — more complex mental model, harder to debug "why did this run?".
- **Eliminate `verify-build` entirely**: rejected, see "Build count".
- **Artifact reuse PR→release**: rejected, complex for marginal gain.
