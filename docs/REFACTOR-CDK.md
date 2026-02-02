# Refactoring from SAM to CDK: Architecture & Design Decisions

This document captures the architectural decisions and tradeoffs discussed when refactoring the IAM Roles Anywhere infrastructure from AWS SAM to AWS CDK.

## Background

The original implementation used AWS SAM (Serverless Application Model) for infrastructure deployment:

- **Three SAM stacks**: `account-rootca-stack` → `account-iamra-stack` → `host-stack`
- **Two Lambda functions**: `ca_generator` and `certificate_issuer`
- **SAM CLI dependency**: The CLI shelled out to `sam build` and `sam deploy`
- **Bundled templates**: YAML templates bundled in `iam_ra_cli.data.cloudformation`

### Pain Points with SAM

1. **SAM CLI is heavy**: Requires Docker for consistent builds, has complex dependency chain
2. **YAML templates are verbose**: Hard to maintain, no type safety, no IDE support
3. **Dependency management**: SAM's Lambda bundling is opaque and hard to customize
4. **Nix integration**: SAM CLI doesn't play well with Nix's reproducibility model
5. **Testing**: No good story for unit testing SAM templates

## Design Goals

1. **Eliminate SAM CLI dependency** - Use CDK instead
2. **Type-safe infrastructure** - Leverage TypeScript for CDK code
3. **Single language for infra** - All CDK code AND Lambda handlers in TypeScript
4. **Clean Nix integration** - All dependencies managed via Nix
5. **Leverage CDK's power** - Use inheritance, polymorphism, and constructs properly

---

## Evolution of CDK Language Choice

### Initial Attempt: Python CDK

We initially attempted to use Python CDK to keep everything in one language:

```
iam-ra-cli/     # Python CLI
iam-ra-cdk/     # Python CDK (attempted)
```

**Problems encountered:**

1. **CDK CLI is Node.js**: The `cdk` command requires Node.js regardless of which language you write CDK code in
2. **Pre-synthesis doesn't work**: CDK synth produces account-bound templates with asset hashes
3. **CDK Bootstrap requirement**: CDK expects a bootstrap stack with S3 bucket for assets

### The Key Question

> Do we *absolutely* need the CDK CLI (Node.js) to deploy stacks on user machines?

**Answer: Yes.** The CDK CLI handles:
- Asset bundling and upload to S3
- Bootstrap stack verification
- CloudFormation deployment with proper asset references
- Rollback and drift detection

### Decision: TypeScript CDK + Node.js Runtime

Since Node.js is required anyway, **TypeScript CDK is the better choice**:

| Factor | Python CDK | TypeScript CDK |
|--------|------------|----------------|
| CDK CLI required | Yes (Node.js) | Yes (Node.js) |
| Language support | Second-class | First-class (native) |
| Type inference | Weaker | Excellent |
| IDE support | Good | Excellent |
| Documentation | Often lags | Primary docs |
| Lambda bundling | `PythonFunction` (Docker) | `NodejsFunction` (esbuild) |

**Trade-off accepted**: Node.js becomes a runtime dependency, but Nix manages this cleanly.

---

## Architecture Decision: All TypeScript (Including Lambdas)

### Why Not Python Lambdas?

Initially we considered keeping Python for Lambda handlers. But this adds complexity:
- Mixed languages in the CDK package
- Different bundling strategies (Docker for Python vs esbuild for TypeScript)
- Context switching between languages

### TypeScript Lambdas with NodejsFunction

CDK's `NodejsFunction` provides excellent TypeScript Lambda support:

```typescript
import { NodejsFunction } from 'aws-cdk-lib/aws-lambda-nodejs';

const handler = new NodejsFunction(this, 'CertIssuer', {
  entry: path.join(__dirname, '../lambdas/cert-issuer.ts'),
  handler: 'handler',
  runtime: lambda.Runtime.NODEJS_20_X,
  timeout: Duration.minutes(15),
  bundling: {
    // esbuild handles TypeScript compilation and tree-shaking
    minify: true,
    sourceMap: true,
  },
});
```

**Benefits:**
- Single language throughout
- Fast bundling with esbuild (no Docker needed)
- Full type safety in Lambda handlers
- Native AWS SDK v3 with TypeScript types

### Crypto Operations in TypeScript

Node.js has excellent crypto support:

```typescript
import * as crypto from 'node:crypto';
import * as x509 from '@peculiar/x509';

// EC P-256 key generation (native Node.js)
const keys = await crypto.webcrypto.subtle.generateKey(
  { name: 'ECDSA', namedCurve: 'P-256' },
  true,
  ['sign', 'verify']
);

// X.509 certificate operations (@peculiar/x509 library)
const cert = await x509.X509CertificateGenerator.create({
  subject: `CN=${hostname}`,
  issuer: caCert.subject,
  publicKey: keys.publicKey,
  signingKey: caPrivateKey,
  // ...
});
```

---

## Architecture Decision: Async Handling with SDK Waiters

### The Problem: PCA Certificate Issuance is Async

When issuing certificates via ACM Private CA:
1. `IssueCertificate` returns immediately with a certificate ARN
2. The actual certificate isn't ready yet
3. Need to poll `GetCertificate` until it succeeds

### Options Considered

| Approach | Complexity | Max Wait Time | Notes |
|----------|------------|---------------|-------|
| **SDK Waiter** | Lowest | Lambda timeout (15 min) | Built into AWS SDK |
| **Provider.isCompleteHandler** | Medium | Configurable | CDK manages polling |
| **WaiterStateMachine** | Higher | Up to 1 year | Step Functions |

### Decision: SDK Waiter (Simplest First)

The AWS SDK v3 has built-in waiters for ACM PCA:

```typescript
import { 
  ACMPCAClient,
  IssueCertificateCommand,
  GetCertificateCommand,
  waitUntilCertificateIssued,
} from '@aws-sdk/client-acm-pca';

// Issue certificate
const issueResponse = await client.send(new IssueCertificateCommand({
  CertificateAuthorityArn: pcaArn,
  Csr: csrBuffer,
  SigningAlgorithm: 'SHA256WITHECDSA',
  Validity: { Type: 'DAYS', Value: validityDays },
}));

// Wait for issuance (SDK handles polling internally)
await waitUntilCertificateIssued(
  { client, maxWaitTime: 900 }, // 15 minutes (Lambda max)
  {
    CertificateAuthorityArn: pcaArn,
    CertificateArn: issueResponse.CertificateArn!,
  }
);

// Get the certificate
const certResponse = await client.send(new GetCertificateCommand({
  CertificateAuthorityArn: pcaArn,
  CertificateArn: issueResponse.CertificateArn!,
}));
```

**Future consideration**: If we hit the 15-minute Lambda timeout in practice, we'll refactor to use `Provider.isCompleteHandler` for longer polling windows.

---

## Architecture Decision: CDK Custom Resources

### No More crhelper!

CDK's `Provider` construct handles the CloudFormation custom resource protocol:

```typescript
import * as cr from 'aws-cdk-lib/custom-resources';

const provider = new cr.Provider(this, 'CertIssuerProvider', {
  onEventHandler: certIssuerLambda,
  // No isCompleteHandler needed - SDK waiter handles async
});

new CustomResource(this, 'HostCert', {
  serviceToken: provider.serviceToken,
  properties: { hostname, validityDays },
});
```

**Benefits:**
- Lambda returns plain objects, Provider formats CloudFormation response
- No need for crhelper or custom response handling
- Built-in error handling and logging

---

## Architecture Decision: CA Mode Polymorphism

### Problem: Conditional Logic Explosion

The SAM templates had complex conditions for different CA modes:
- `UseSelfManagedCA`, `CreatePCA`, `UseExistingPCA`, `UsePCA`

### Solution: Interface + Implementations

```typescript
interface ICertificateAuthority {
  readonly mode: 'self-managed' | 'pca-existing' | 'pca-managed';
  readonly trustAnchorSource: rolesanywhere.CfnTrustAnchor.SourceProperty;
  
  grantCertificateIssuance(grantee: lambda.IFunction): void;
  getSigningCredentials(): SigningCredentials;
}

// Three implementations:
class SelfManagedCA extends Construct implements ICertificateAuthority { }
class ExistingPcaCA extends Construct implements ICertificateAuthority { }
class ManagedPcaCA extends Construct implements ICertificateAuthority { }
```

---

## Architecture Decision: Stack Structure

### Decision: Separate Stacks, Elegant Patterns

Keep separate stacks per host for:
- **Independent lifecycle**: Add/remove hosts without affecting others
- **Blast radius containment**: Failed deploy doesn't break other hosts
- **CloudFormation limits**: Each host creates ~10 resources

---

## Final Architecture (All TypeScript CDK)

```
iam-roles-anywhere/
├── flake.nix                         # Provides nodejs, cdk cli, python
├── pyproject.toml                    # UV workspace root (CLI only)
├── uv.lock
│
├── iam-ra-cli/                       # Python CLI
│   ├── pyproject.toml
│   └── iam_ra_cli/
│       ├── main.py                   # Click CLI
│       ├── commands/
│       │   ├── init.py               # Shells out to `cdk deploy`
│       │   ├── onboard.py            # Shells out to `cdk deploy`
│       │   └── status.py             # Pure boto3
│       └── lib/
│           ├── cdk.py                # CDK deployment wrapper
│           └── aws.py                # boto3 helpers
│
├── iam-ra-cdk/                       # TypeScript CDK (ALL TypeScript!)
│   ├── package.json
│   ├── tsconfig.json
│   ├── cdk.json
│   ├── bin/
│   │   └── app.ts                    # CDK app entry point
│   ├── lib/
│   │   ├── stacks/
│   │   │   ├── infra-stack.ts        # CA + Trust Anchor + Cert Issuer
│   │   │   └── host-stack.ts         # Per-host resources
│   │   ├── constructs/
│   │   │   ├── certificate-authority/
│   │   │   │   ├── types.ts          # ICertificateAuthority interface
│   │   │   │   ├── self-managed.ts   # Lambda-generated CA
│   │   │   │   ├── pca-existing.ts   # Existing ACM PCA
│   │   │   │   ├── pca-managed.ts    # CDK-created ACM PCA
│   │   │   │   └── index.ts          # Factory + exports
│   │   │   ├── certificate-issuer.ts # Provider + TypeScript Lambda
│   │   │   └── host.ts               # IamRaHost construct
│   │   └── lambdas/                  # TypeScript Lambda handlers!
│   │       ├── ca-generator.ts       # Generates self-managed CA
│   │       └── cert-issuer.ts        # Issues host certificates
│   └── test/
│       ├── infra-stack.test.ts
│       └── host-stack.test.ts
│
├── modules/                          # NixOS/Darwin modules (unchanged)
├── lib/                              # Nix lib functions (unchanged)
└── docs/
    ├── REFACTOR-CDK.md               # This document
    └── TODO.md                       # Implementation tracking
```

---

## Runtime Dependencies

| Component | Runtime Dependencies |
|-----------|---------------------|
| `iam-ra-cli` (status, secrets) | Python, boto3 |
| `iam-ra-cli` (init, onboard) | Python, boto3, Node.js, CDK CLI |
| `iam-ra-cdk` (direct usage) | Node.js, CDK CLI |

All dependencies are managed by Nix:
- `devShell`: Full environment (Python, Node.js, CDK CLI, AWS CLI)
- `packages.iam-ra-cli`: CLI package (Python only for read-only ops)
- `packages.iam-ra-full`: CLI + CDK + Node.js for deployment

---

## Key Design Principles

1. **Single language for infrastructure**: TypeScript for CDK AND Lambda handlers
2. **Leverage the type system**: Interfaces for CA modes, not conditionals
3. **Composition over inheritance**: Constructs compose, stacks orchestrate
4. **Sane defaults with escape hatches**: Default IAM policies + custom overrides
5. **Simple async first**: SDK waiters, upgrade to isCompleteHandler if needed
6. **Let CDK handle complexity**: Provider for custom resources, NodejsFunction for bundling

---

## Timeout Configuration

All timeouts are set to maximum values. If we hit these limits, we'll refactor to use `Provider.isCompleteHandler`:

| Component | Timeout | Notes |
|-----------|---------|-------|
| CA Generator Lambda | 15 minutes | Crypto operations are fast |
| Cert Issuer Lambda | 15 minutes | Includes SDK waiter for PCA |
| Provider totalTimeout | 30 minutes | CloudFormation custom resource |
| SDK waitUntilCertificateIssued | 15 minutes | Within Lambda timeout |

---

## References

- [AWS CDK TypeScript Reference](https://docs.aws.amazon.com/cdk/api/v2/docs/aws-construct-library.html)
- [CDK Custom Resources](https://docs.aws.amazon.com/cdk/api/v2/docs/aws-cdk-lib.custom_resources-readme.html)
- [CDK NodejsFunction](https://docs.aws.amazon.com/cdk/api/v2/docs/aws-cdk-lib.aws_lambda_nodejs-readme.html)
- [AWS SDK v3 ACM PCA Waiters](https://docs.aws.amazon.com/AWSJavaScriptSDK/v3/latest/client/acm-pca/)
- [@peculiar/x509 Library](https://github.com/PeculiarVentures/x509)
- [IAM Roles Anywhere Documentation](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.html)
