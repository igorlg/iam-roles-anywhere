# Implementation Plan: Multi-Identity Support

Status: Agreed, ready to implement

This document captures the implementation plan for adding multi-role and
multi-identity (multi-account) support to `iam-roles-anywhere`. It builds
on a pre-design gap analysis conducted earlier (not committed to this repo;
kept as a local working document).

The gap analysis identified three scenarios:

1. **Single role, single cert** — fully supported today.
2. **Multiple roles, same cert** (same trust anchor / same account) —
   supported at the Nix module level, but not at the CLI level.
3. **Multiple certs across different trust anchors / accounts** — not
   supported at all; Nix module is a singleton and CLI has no concept of
   a host belonging to multiple identities.

This document lays out how we close the gaps, in what order, and where the
open questions landed.

---

## Design decisions (locked in)

From discussion on top of the gap analysis:

### 1. Multi-account = multi-namespace, not multi-scope

The gap analysis framed scenario 3 (personal + work accounts on one laptop)
as "host has multiple scopes". We've agreed that the cleaner model is **one
namespace per AWS account**:

- A namespace owns its own SSM parameter, S3 bucket, KMS key — all of which
  are single-account AWS resources. One namespace literally cannot span two
  accounts.
- "Personal" and "work" become two independent namespaces, each with their
  own state, own CA, own host records.
- The Nix module's proposed `identities.<name>` attrset maps 1:1 to
  **namespaces**, not to a new "scope = account" concept.
- **Scope** keeps its existing meaning: an optional CA subdivision *within*
  a namespace (e.g. different trust anchors for prod vs dev inside one
  account).

Consequence: scenario 3 requires almost no CLI change beyond scenario 2 —
it's "run onboard in N namespaces with different AWS credentials, the Nix
module aggregates".

### 2. Account ID tracked explicitly in state

Add `account_id: str` to:

- `NamespaceInfo` (new) — tracked at `iam-ra init` time from `ctx.account_id`
- `CA` (existing) — derived from `trust_anchor_arn.account` at CA setup

Purposes: status display, pre-flight validation (catch "wrong account"
mismatches early), and grounding the multi-account story in explicit data.

The existing `Arn.account` property makes this effectively free — no schema
archaeology needed.

### 3. Hard-cut migration, explicit migrate tool

No backward-compat shims in the Nix module reading two SOPS schemas. Users
run `iam-ra migrate` to transform state + SOPS files when they update the
CLI. Cleanly isolates "here's the migration code" from "here's the current
code", simpler to reason about, simpler to remove later.

Code that exists only for migration gets tagged `# MIGRATION_SHIM` so it's
grep-able for future cleanup.

### 4. SOPS path: all namespaces suffixed, legacy warn-only

- **Write path**: always `secrets/hosts/{hostname}/iam-ra-{namespace}.yaml`.
- **Read path**: prefers suffixed form. For `namespace=default` only, falls
  back to legacy `iam-ra.yaml` if suffixed doesn't exist, with a warning
  pointing at `iam-ra migrate sops-paths`.
- No silent renames. Users see the warning, run the migrate command when
  ready, update their Nix references.
- `iam-ra migrate sops-paths` command: dry-run by default, `--apply` to
  actually rename.

### 5. CloudFormation: one stack per (host, scope)

Existing Host CFN stack layout: `iam-ra-{namespace}-host-{hostname}`. For
scenario 3 (within-namespace scope subdivision), extend to
`iam-ra-{namespace}-host-{hostname}-{scope}` when scope ≠ default. Symmetric
with existing role stacks being per-name. Enables partial teardown
(`iam-ra host offboard --scope X` removes just one identity).

### 6. Terminology: dual vocabulary, each in its place

- **Nix module API** uses `identity` (more user-friendly, matches AWS's
  identity model at the conceptual level). `identities.<name>` maps to a
  namespace.
- **CLI flags + state model** uses `scope` for within-namespace CA
  subdivision. Namespace stays `namespace`.
- Users generally interact with identities via Nix; CLI users see namespace
  + scope as they already do.

### 7. Sequencing: two PRs, each a hard cut

- **PR 1**: scenario 2 (multi-role, same cert within one namespace). State
  schema v3, SOPS schema v2, `add-role`/`remove-role` commands,
  `iam-ra migrate` updated. Nix module updated to consume v2 SOPS.
- **PR 2**: scenario 3 (multi-namespace identities). Nix module gains
  `identities` attrset, `iam-ra migrate sops-paths` command, documentation
  of cross-account workflow.

### 8. K8s and downstream factory deferred

K8s has the same multi-identity issue but we're shipping hosts first. See
[K8s notes](#k8s-integration-notes) below for decisions we make now that
affect the K8s design later.

`igorlg/nix`'s `factory.iamRa` gets updated in a separate PR in that repo,
after these land.

---

## PR 1: scenario 2 — multi-role, same cert

### Goal

One host, one cert, multiple AWS roles (all under the same trust anchor /
same scope / same account). Example: `work-admin`, `work-readonly`,
`work-deploy` all assumable from one cert.

### State schema changes (v2 → v3)

New dataclass:

```python
@dataclass(frozen=True)
class NamespaceInfo:
    """Namespace-level metadata, populated at `iam-ra init` time."""
    account_id: str
    region: str
    # Future: created_at, iam-ra version at creation, etc.
```

Modified dataclasses:

```python
@dataclass(frozen=True)
class CA:
    stack_name: str
    mode: CAMode
    trust_anchor_arn: Arn
    pca_arn: Arn | None = None
    account_id: str | None = None  # NEW - derived from trust_anchor_arn.account

@dataclass(frozen=True)
class Host:
    stack_name: str
    hostname: str
    role_names: tuple[str, ...]    # CHANGED - was role_name: str
    certificate_secret_arn: Arn
    private_key_secret_arn: Arn
    scope: str = "default"          # NEW - explicit scope on host

@dataclass
class State:
    namespace: str
    region: str
    version: str
    namespace_info: NamespaceInfo | None = None  # NEW
    init: Init | None = None
    cas: dict[str, CA] = field(default_factory=dict)
    roles: dict[str, Role] = field(default_factory=dict)
    hosts: dict[str, Host] = field(default_factory=dict)
    k8s_clusters: dict[str, K8sCluster] = field(default_factory=dict)
    k8s_workloads: dict[str, K8sWorkload] = field(default_factory=dict)
```

Migration (v2 → v3) in `State.from_json`:

```python
# MIGRATION_SHIM (remove in v4.0): v2 Host had role_name: str; v3 has role_names: tuple[str, ...]
if "role_name" in host_raw and "role_names" not in host_raw:
    host_raw["role_names"] = (host_raw.pop("role_name"),)

# MIGRATION_SHIM (remove in v4.0): v2 Host had no explicit scope; derive from role
if "scope" not in host_raw:
    role_name = host_raw["role_names"][0]  # use first role for backfill
    host_raw["scope"] = state_raw["roles"][role_name].get("scope", "default")

# MIGRATION_SHIM (remove in v4.0): v2 CA had no account_id; extract from trust_anchor_arn
for scope_name, ca_raw in state_raw.get("cas", {}).items():
    if "account_id" not in ca_raw:
        ca_raw["account_id"] = Arn(ca_raw["trust_anchor_arn"]).account

# MIGRATION_SHIM (remove in v4.0): v2 had no NamespaceInfo; backfill from init + a sensible default
if "namespace_info" not in state_raw and state_raw.get("init") is not None:
    state_raw["namespace_info"] = {
        "account_id": Arn(state_raw["init"]["bucket_arn"]).account,
        "region": state_raw.get("region", "ap-southeast-2"),
    }
```

### SOPS schema v2

```yaml
# One file per (hostname, namespace) at:
# secrets/hosts/{hostname}/iam-ra-{namespace}.yaml

schema_version: v2
certificate: |
  -----BEGIN CERTIFICATE-----
  ...
private_key: |
  -----BEGIN EC PRIVATE KEY-----
  ...
trust_anchor_arn: arn:aws:rolesanywhere:ap-southeast-2:718758479978:trust-anchor/...
region: ap-southeast-2
account_id: "718758479978"   # NEW - for Nix-side validation

profiles:
  admin:
    profile_arn: arn:aws:rolesanywhere:...
    role_arn: arn:aws:iam::718758479978:role/iam-ra-default-admin
  readonly:
    profile_arn: arn:aws:rolesanywhere:...
    role_arn: arn:aws:iam::718758479978:role/iam-ra-default-readonly
```

Design notes:

- `schema_version: v2` at top level. Nix module branches on this; migration
  tool bumps v1 → v2.
- `profiles` is a map keyed by the CLI's role name (not the role ARN
  suffix). This is the user-facing identifier.
- The cert + key are per-identity (per-SOPS-file), not per-profile. Adding
  a profile doesn't require issuing a new cert.

### CLI changes

**Modified**:

- `iam-ra host onboard <host> --role X` — still works for single role.
  Now also supports `--role X,Y,Z` (comma-separated) or repeated
  `--role X --role Y --role Z`. First role determines the scope (validation:
  all roles must share the same scope).

**New**:

- `iam-ra host add-role <host> <role>` — extends an existing host to
  assume another role. Preconditions: role's scope == host's scope. Effect:
  state update + SOPS file update (adds entry to `profiles` map). **No new
  cert issued.**

- `iam-ra host remove-role <host> <role>` — inverse. State update + SOPS
  update. Does not remove the host itself even if it's the last role
  (separate `iam-ra host offboard` for that).

**Modified**:

- `iam-ra status --json` (and others): hosts now report `role_names: [...]`
  instead of `role_name: "..."`.

### Nix module changes

- Read SOPS v2 schema (the `profiles` map becomes the source of truth for
  `programs.iamRolesAnywhere.profiles`).
- **Remove** the ability to configure `profiles` from Nix literals. Profiles
  come from SOPS. This is a behaviour change but matches the "CLI is the
  source of truth" direction.
- Actually, reconsider: some users (downstream factories) provide profile
  info via Nix. We'd keep both options:
  - If SOPS file provides a v2 `profiles` map: that wins.
  - If user configures `profiles` attrset directly in Nix: legacy path,
    marked as `# MIGRATION_SHIM` for future removal.

### Tests

TDD per existing pattern:

1. **State model tests** (`tests/test_models.py`): v2 → v3 migration, new
   `NamespaceInfo`, `Host.role_names` tuple, `CA.account_id` derivation.
2. **Workflow tests** (`tests/test_workflow_host.py`): `add-role` adds
   without reissuing cert, validates scope match, updates SOPS.
   `remove-role` removes + updates SOPS.
3. **SOPS schema tests**: v1 read fallback, v2 write, migration from v1 → v2.
4. **Command tests** (`tests/test_commands_host.py`): new `--role X,Y`
   handling, JSON output shape, error cases.

### Out of scope for PR 1

- Nix module `identities` attrset (scenario 3) — stays singleton, but per-
  namespace SOPS file naming introduced so PR 2 can build on it.
- Cross-account workflow.
- K8s changes.

---

## PR 2: scenario 3 — multi-namespace identities

### Goal

One host, multiple certs under different trust anchors / accounts. Example:
a laptop that needs both `personal-admin` (account A, personal trust
anchor) and `work-admin` (account B, work trust anchor).

### Nix module: `identities` attrset

```nix
programs.iamRolesAnywhere = {
  enable = true;
  user = "alice";

  identities = {
    work = {
      # Cert + key for this identity
      certificate = {
        certPath = config.sops.secrets."iam-ra/work/cert".path;
        keyPath  = config.sops.secrets."iam-ra/work/key".path;
      };
      # Account-level config
      trustAnchorArn = "arn:aws:rolesanywhere:ap-southeast-2:718758479978:...";
      region = "ap-southeast-2";
      # Multiple profiles sharing this cert (= scenario 2)
      profiles = {
        work-admin    = { profileArn = "..."; roleArn = "..."; };
        work-readonly = { profileArn = "..."; roleArn = "..."; };
      };
    };
    personal = {
      certificate.certPath = config.sops.secrets."iam-ra/personal/cert".path;
      certificate.keyPath  = config.sops.secrets."iam-ra/personal/key".path;
      trustAnchorArn = "arn:aws:rolesanywhere:ap-southeast-2:987098549565:...";
      region = "ap-southeast-2";
      profiles.personal-admin = { profileArn = "..."; roleArn = "..."; };
    };
  };
};
```

**Hard cut**: the flat top-level `certificate` / `trustAnchorArn` / `region`
/ `profiles` options get removed. Users upgrading need to move their config
into `identities.default = { ... }`. The `iam-ra migrate` tool offers a
Nix config rewriter for common patterns; less common patterns need manual
migration (documented).

Generated AWS CLI profiles:

- Profile names must be unique across all identities (validated at eval
  time in `module-validation.nix`).
- `makeDefault` stays global: exactly one profile, across all identities,
  can be the `[default]` profile. Enforced at eval time.
- Per-identity `credential_process` commands use the identity's own cert
  and trust anchor ARN.

### CLI: cross-namespace onboarding workflow

No real new CLI commands needed — `iam-ra host onboard` already takes
`--namespace`. The workflow becomes:

```bash
# Personal identity (using personal AWS credentials)
AWS_PROFILE=personal iam-ra host onboard my-laptop --namespace personal --role personal-admin

# Work identity (using work AWS credentials)
AWS_PROFILE=work iam-ra host onboard my-laptop --namespace work --role work-admin
AWS_PROFILE=work iam-ra host add-role my-laptop work-readonly --namespace work
```

Result: two SOPS files, one Nix `identities` attrset entry per namespace.

### `iam-ra migrate sops-paths`

Separate subcommand of the existing migrate workflow.

**Dry-run mode (default)**:

```
$ iam-ra migrate sops-paths
Scanning secrets/hosts/ for legacy-named SOPS files...
Found 2 legacy files:
  secrets/hosts/web-01/iam-ra.yaml  →  secrets/hosts/web-01/iam-ra-default.yaml
  secrets/hosts/db-01/iam-ra.yaml   →  secrets/hosts/db-01/iam-ra-default.yaml

Run with --apply to rename these files. You will also need to update any
Nix references (e.g. sops.secrets.<...>.sopsFile = ...) to match.
```

**Apply mode**:

```
$ iam-ra migrate sops-paths --apply
Renamed: secrets/hosts/web-01/iam-ra.yaml → iam-ra-default.yaml
Renamed: secrets/hosts/db-01/iam-ra.yaml → iam-ra-default.yaml

Next: update your Nix configuration to reference the new paths:
  sops.secrets."iam-ra/cert".sopsFile = ./secrets/hosts/web-01/iam-ra-default.yaml;

Or grep for the old paths:
  grep -rn 'iam-ra\.yaml' *.nix
```

### Account mismatch pre-flight

Add a validation layer in `iam-ra host onboard`: before issuing a cert,
compare `ctx.account_id` (current AWS credentials) against
`state.namespace_info.account_id`. If mismatched, fail fast:

```
Error: Namespace 'personal' is in AWS account 987098549565, but your
current AWS credentials are for account 718758479978. Use AWS_PROFILE or
--profile to switch to the correct account.
```

This catches the very common "forgot to switch AWS profiles" footgun.

### Tests

- Nix module evaluation tests (`nix flake check`): verify `identities` with
  multiple entries produces correct `programs.awscli.profiles`.
- Duplicate profile name detection across identities.
- `iam-ra migrate sops-paths`: dry-run + apply + idempotency (running twice
  is a no-op).
- Account-mismatch pre-flight: both success + rejection paths.

### Out of scope for PR 2

- K8s.
- Auto-updating Nix references in `sops.secrets.<...>.sopsFile = ...`
  declarations. Users update their own Nix.

---

## Open questions that survived

1. **`makeDefault` across identities**: enforce "exactly one across all
   identities can set it"? Or allow per-identity default (which would
   conflict with AWS CLI's single `[default]` profile)? **Decision: global,
   exactly one**. Validated at Nix eval time.

2. **Region per profile vs per identity**: the plan puts `region` at the
   identity level. Is that enough for scenarios that span regions within
   one AWS account? **Current decision: yes, per-identity**. If needed
   later, add `profiles.<name>.region` as an override. Keeps simple case
   simple.

3. **`iam-ra host rotate-cert`?**: rotating a cert today is
   `host onboard --overwrite`. With multi-role hosts, does rotation preserve
   the role list? **Decision: yes**. Rotate = re-issue cert under existing
   scope, keep `role_names` unchanged. Add explicit `iam-ra host
   rotate-cert` command in PR 1.

4. **Cert expiry handling**: not addressed yet. Worth tracking expiry in
   state so `iam-ra status` can warn of expiring certs. **Deferred** to a
   later PR.

---

## K8s integration notes

K8s has a structurally identical problem: `iam-ra k8s onboard <workload>
--role <R>` maps 1:1 like hosts. Multi-role (scenario 2 analogue) and
multi-cluster-per-workload (scenario 3 analogue) aren't supported.

**Decisions made now that affect K8s design later**:

- **Multi-role for K8s workloads**: same `role_names: tuple[str, ...]`
  pattern on `K8sWorkload`. Extend whenever K8s gets the multi-identity
  treatment.
- **Multi-cluster-per-workload**: likely analogous to multi-namespace-per-
  host, but K8s cert-manager flow differs (K8s issues certs, not us). Needs
  its own design; not a direct port.
- **K8s cluster has no account_id** in current state. If a workload ever
  needs to assume roles in multiple accounts, we'd need to track account
  per cluster or per workload. **Deferred design question**.
- **Manifest output**: current `iam-ra k8s onboard` outputs a single
  manifest bundle. Multi-role would bundle multiple AWS CLI profile configs
  into the workload's ConfigMap — consistent with the host story.

---

## Ordering + dependencies

```text
PR 1 (scenario 2)
  ├─ state schema v2 → v3
  ├─ SOPS schema v1 → v2
  ├─ iam-ra migrate: state + SOPS content (not paths yet)
  ├─ CLI: add-role, remove-role, rotate-cert
  ├─ Nix module: read v2 SOPS
  └─ Tests
          │
          │ (merge, release as minor version bump)
          ▼
PR 2 (scenario 3)
  ├─ Nix module: identities attrset (hard cut)
  ├─ iam-ra migrate sops-paths
  ├─ Account-mismatch pre-flight
  ├─ Docs: cross-account workflow
  └─ Tests
          │
          │ (merge, release as minor version bump)
          ▼
(followups, separate PRs)
  ├─ igorlg/nix factory update
  ├─ K8s multi-identity (when ready)
  └─ Cert expiry tracking
```

Each PR is self-contained and releasable. Minor version bump per PR
because the state schema change in PR 1 and the Nix module API change in
PR 2 are both technically breaking, but backward-compatible via migration
tooling — not a major bump.

---

## Costs

- **PR 1**: medium. State migration + SOPS schema + 3 new CLI commands +
  Nix module schema detection. Estimated ~1 week of focused work.
- **PR 2**: small-to-medium. Nix module refactor (self-contained), one new
  CLI migration command, docs. ~half a week.
- **Ongoing**: none. Once `# MIGRATION_SHIM` markers are removed at v4, no
  extra maintenance beyond normal feature work.

---

## Testing strategy

TDD per project convention:

1. Write state model tests first, covering both forward migration and v3
   read/write round-trips.
2. Write SOPS schema tests covering v1 read fallback, v2 write, migration.
3. Write workflow tests for `add-role`, `remove-role`, `rotate-cert` using
   moto to mock AWS.
4. Write command tests for CLI surface (JSON outputs, error cases).
5. For PR 2: Nix flake check tests, `iam-ra migrate sops-paths` dry-run
   + apply tests with tmp_path fixtures.

Existing CI tooling (`nix.yaml`, `python.yaml`, `docs.yaml`) handles the
rest. No new workflows needed.
