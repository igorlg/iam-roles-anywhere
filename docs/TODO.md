# SAM to CDK Refactoring - Implementation TODO

**Started**: 2026-02-02  
**Branch**: `refactor-cdk`  
**Design Doc**: [REFACTOR-CDK.md](./REFACTOR-CDK.md)

---

## Status Overview

| Phase | Status | Notes |
|-------|--------|-------|
| Phase 1: Documentation | ✅ Complete | Architecture decisions documented |
| Phase 2: Nix Setup | 🔄 In Progress | Add Node.js + CDK CLI |
| Phase 3: CDK Design | ⏳ Pending | First principles redesign |
| Phase 4: Implementation | ⏳ Pending | TypeScript CDK + simplified Lambdas |
| Phase 5: CLI Integration | ⏳ Pending | Update Python CLI |
| Phase 6: Testing | ⏳ Pending | End-to-end validation |

---

## Phase 1: Documentation ✅

- [x] Document SAM → Python CDK → TypeScript CDK evolution
- [x] Document CDK CLI runtime dependency decision
- [x] Document CA mode polymorphism approach
- [x] Document stack structure decisions
- [x] Document per-host IAM customization design

---

## Phase 2: Nix Setup

### 2.1 Add Node.js and CDK CLI to devShell
- [ ] Add `nodejs_20` to devShell packages
- [ ] Add `nodePackages.aws-cdk` to devShell packages
- [ ] Verify `cdk --version` works in `nix develop`

### 2.2 Update Flake Outputs (for runtime)
- [ ] Create `packages.iam-ra-full` that includes Node.js + CDK CLI
- [ ] Keep `packages.iam-ra-cli` as Python-only (for read-only operations)
- [ ] Document the package variants

---

## Phase 3: CDK Application Design

### 3.1 Certificate Authority Abstraction
Design interface and implementations for CA modes:

```typescript
interface ICertificateAuthority {
  readonly mode: 'self-managed' | 'pca-create' | 'pca-existing';
  readonly trustAnchorSource: SourceProperty;
  grantCertificateIssuance(lambda: lambda.Function): void;
  getSigningCredentials(): SigningCredentials;
}
```

Implementations:
- [ ] `SelfManagedCA` - Lambda-generated CA cert/key
- [ ] `ExistingPcaCA` - Reference existing ACM PCA by ARN
- [ ] `ManagedPcaCA` - Create new ACM PCA via CDK

### 3.2 Certificate Issuer with Provider
- [ ] Design `CertificateIssuerConstruct` using `cr.Provider`
- [ ] `onEventHandler` - Generate key pair, create CSR, sign/issue cert
- [ ] `isCompleteHandler` - Poll for PCA cert completion (async)
- [ ] Remove crhelper dependency from Lambda code

### 3.3 Host Construct
- [ ] Design `IamRaHost` construct with:
  - IAM Role with Roles Anywhere trust policy
  - IAM Roles Anywhere Profile
  - Certificate via custom resource
  - Secrets Manager secrets for cert/key
  - SSM Parameters for discovery
- [ ] Support custom IAM policies (managed + inline)
- [ ] Support configurable session duration
- [ ] Support configurable certificate validity

### 3.4 Stack Structure
- [ ] `IamRaInfraStack` - CA + Trust Anchor + Cert Issuer (once per account)
- [ ] `IamRaHostStack` - Per-host resources (one per host)
- [ ] Design CLI → CDK context passing mechanism

---

## Phase 4: TypeScript CDK Implementation

### 4.1 Project Setup
- [ ] Remove Python CDK code (`iam-ra-cdk/iam_ra_cdk/`)
- [ ] Initialize TypeScript CDK project:
  ```bash
  cd iam-ra-cdk
  cdk init app --language typescript
  ```
- [ ] Configure `tsconfig.json` for strict mode
- [ ] Add ESLint + Prettier configuration

### 4.2 Directory Structure
```
iam-ra-cdk/
├── package.json
├── tsconfig.json
├── cdk.json
├── lib/
│   ├── app.ts
│   ├── stacks/
│   │   ├── infra-stack.ts
│   │   └── host-stack.ts
│   ├── constructs/
│   │   ├── certificate-authority/
│   │   │   ├── index.ts
│   │   │   ├── self-managed.ts
│   │   │   ├── pca-existing.ts
│   │   │   └── pca-managed.ts
│   │   ├── certificate-issuer.ts
│   │   └── host.ts
│   └── lambdas/
│       ├── ca-generator/
│       │   ├── index.py
│       │   └── requirements.txt
│       └── cert-issuer/
│           ├── index.py
│           └── requirements.txt
└── test/
    ├── infra-stack.test.ts
    └── host-stack.test.ts
```

### 4.3 Implement Constructs
- [ ] `ICertificateAuthority` interface
- [ ] `SelfManagedCA` construct
- [ ] `ExistingPcaCA` construct  
- [ ] `ManagedPcaCA` construct
- [ ] `CertificateIssuer` construct (with Provider)
- [ ] `IamRaHost` construct

### 4.4 Implement Stacks
- [ ] `IamRaInfraStack`
- [ ] `IamRaHostStack`
- [ ] CDK App entry point with context handling

### 4.5 Simplify Lambda Handlers
- [ ] `ca-generator/index.py` - Remove crhelper, return dict
- [ ] `cert-issuer/index.py` - Remove crhelper, use Provider pattern
- [ ] Update `requirements.txt` (remove crhelper)

---

## Phase 5: CLI Integration

### 5.1 CDK Deployer Module
- [ ] Create `iam_ra_cli/lib/cdk.py`:
  - `CDKDeployer` class
  - Subprocess wrapper for `cdk deploy`
  - Context parameter passing
  - Output parsing

### 5.2 Update Commands
- [ ] Update `commands/init.py` to use CDK
- [ ] Update `commands/onboard.py` to use CDK
- [ ] Ensure `commands/status.py` works without CDK (boto3 only)

### 5.3 Remove SAM Code
- [ ] Delete `iam_ra_cli/data/cloudformation/`
- [ ] Delete `iam_ra_cli/lib/templates.py` (SAMRunner)
- [ ] Update `pyproject.toml` to remove data files

---

## Phase 6: Testing & Validation

### 6.1 CDK Tests
- [ ] Snapshot tests for synthesized templates
- [ ] Fine-grained assertion tests for critical resources
- [ ] Test CA mode polymorphism

### 6.2 Integration Tests
- [ ] Deploy infra stack to test account (self-managed mode)
- [ ] Deploy host stack
- [ ] Verify certificate issuance
- [ ] Verify credential retrieval
- [ ] Test with ACM PCA mode (if available)

### 6.3 CLI Tests
- [ ] Test `iam-ra init` end-to-end
- [ ] Test `iam-ra onboard` end-to-end
- [ ] Test `iam-ra status` (should work without CDK)

### 6.4 Nix Tests
- [ ] `nix build .#iam-ra-cli` works
- [ ] `nix build .#iam-ra-full` works
- [ ] `nix develop` provides all tools

---

## File Changes Summary

### Files to Create
- `iam-ra-cdk/package.json`
- `iam-ra-cdk/tsconfig.json`
- `iam-ra-cdk/lib/app.ts`
- `iam-ra-cdk/lib/stacks/infra-stack.ts`
- `iam-ra-cdk/lib/stacks/host-stack.ts`
- `iam-ra-cdk/lib/constructs/certificate-authority/*.ts`
- `iam-ra-cdk/lib/constructs/certificate-issuer.ts`
- `iam-ra-cdk/lib/constructs/host.ts`
- `iam-ra-cdk/lib/lambdas/ca-generator/index.py`
- `iam-ra-cdk/lib/lambdas/cert-issuer/index.py`
- `iam_ra_cli/lib/cdk.py`

### Files to Delete
- `iam-ra-cdk/iam_ra_cdk/` (Python CDK code)
- `iam-ra-cdk/pyproject.toml` (replaced by package.json)
- `iam-ra-cli/iam_ra_cli/data/cloudformation/` (SAM templates)
- `iam-ra-cli/iam_ra_cli/lib/templates.py` (SAMRunner)

### Files to Modify
- `flake.nix` - Add Node.js, CDK CLI
- `shells.nix` - Update devShell
- `pyproject.toml` - Remove iam-ra-cdk from workspace
- `iam-ra-cli/pyproject.toml` - Remove data files, CDK optional dep

---

## Commands Cheat Sheet

```bash
# Development setup
nix develop

# CDK commands (in iam-ra-cdk/)
cdk synth                              # Synthesize all stacks
cdk synth IamRaInfraStack              # Synth specific stack
cdk deploy IamRaInfraStack             # Deploy infra
cdk deploy IamRaHostStack-myhost       # Deploy host

# CLI commands
uv run iam-ra init --region us-east-1
uv run iam-ra onboard myhost --region us-east-1
uv run iam-ra status

# Testing
cd iam-ra-cdk && npm test              # CDK tests
uv run pytest                          # Python tests

# Nix builds
nix build .#iam-ra-cli
nix build .#iam-ra-full
nix flake check
```

---

## Notes & Decisions Log

### 2026-02-02: Pivot from Python CDK to TypeScript CDK
- **Reason**: CDK CLI requires Node.js regardless of CDK language
- **Implication**: If Node.js is required anyway, TypeScript is first-class
- **Benefit**: Better types, IDE support, native Provider construct

### 2026-02-02: Keep separate stacks per host
- **Reason**: Independent lifecycle, blast radius containment
- **Alternative considered**: Single stack with all hosts
- **Decision**: Separate stacks, but elegant CDK patterns

### 2026-02-02: Use Provider construct instead of crhelper
- **Reason**: CDK handles CR protocol natively
- **Benefit**: Simplified Lambda code, better async handling
- **Impact**: Lambda handlers become pure business logic
