# IAM Roles Anywhere - CloudFormation Templates

This directory contains CloudFormation templates and Lambda functions for AWS IAM Roles Anywhere infrastructure automation.

## Architecture

**AWS-First Design**: Secrets are generated in AWS (Secrets Manager), backed up to SOPS for disaster recovery.

### Three-Stack Approach

1. **Root CA Stack** (`account-rootca-stack.yaml`): Certificate Authority setup
   - Self-managed CA (Lambda-generated)
   - ACM Private CA (create new or use existing)
   - SSM Parameters for CA configuration

2. **IAM RA Stack** (`account-iamra-stack.yaml`): IAM Roles Anywhere setup
   - Trust Anchor (references CA from rootca stack via SSM)
   - SSM Parameters for account-wide config

3. **Host Stack** (`host-stack.yaml`): Per-host deployment
   - IAM Role with CN-based trust policy
   - IAM Roles Anywhere Profile
   - Certificate Issuer Lambda
   - Host-specific secrets in Secrets Manager
   - SSM Parameters for host config

## Prerequisites

- AWS CLI configured with appropriate credentials
- AWS SAM CLI (`sam` command)
- Python 3.11+ with uv package manager (for Lambda development)
- Nix (for CLI integration)

## Components

- `account-rootca-stack.yaml` - Root CA infrastructure (SAM template)
- `account-iamra-stack.yaml` - IAM Roles Anywhere infrastructure (CloudFormation)
- `host-stack.yaml` - Per-host infrastructure (SAM template)
- `samconfig.toml` - SAM CLI configuration
- `ca_generator/` - Lambda function for self-managed CA generation
- `certificate_issuer/` - Lambda function for host certificate issuance
- `pyproject.toml` - Python dependencies (uv)

## Quick Start

**Recommended**: Use the `iam-ra` CLI for automated workflows (see Phase 2 in TODO.md).

### Deployment with SAM

#### 1. Deploy Root CA Stack (once per AWS account)

Three CA modes are supported:

**Option A: Self-Managed CA** (recommended for <40 hosts, ~$0.80/host/month):

```bash
sam build --config-env rootca
sam deploy --config-env rootca \
  --parameter-overrides CAMode=self-managed
```

**Option B: Create New ACM Private CA** ($400/month + $0.75/cert):

```bash
sam build --config-env rootca
sam deploy --config-env rootca \
  --parameter-overrides \
    CAMode=pca-create \
    PCAKeyAlgorithm=EC_prime256v1 \
    PCASubjectCommonName="My Root CA"
```

**Option C: Use Existing ACM Private CA**:

```bash
sam build --config-env rootca
sam deploy --config-env rootca \
  --parameter-overrides \
    CAMode=pca-existing \
    PCAArn=arn:aws:acm-pca:region:123456789012:certificate-authority/abc123
```

#### 2. Deploy IAM Roles Anywhere Stack (once per AWS account)

```bash
# Build (no Lambda functions, but SAM still processes the template)
sam build --config-env iamra

# Deploy - CAMode must match the rootca stack
sam deploy --config-env iamra \
  --parameter-overrides CAMode=self-managed
```

#### 3. Deploy Host Stack (per host)

```bash
# Build Lambda functions
sam build --config-env host

# Deploy host stack (customize stack name per host)
sam deploy --config-env host \
  --stack-name iam-ra-host-lnv-01 \
  --parameter-overrides Hostname=lnv-01
```

The host stack automatically reads the Trust Anchor ARN from SSM parameters created by the iamra stack.

#### 4. Retrieve Credentials

**Using CLI** (recommended):
```bash
iam-ra onboard-host --hostname lnv-01 --ca-mode self-managed
```

**Manually**:
```bash
aws secretsmanager get-secret-value \
  --secret-id /iam-ra/hosts/lnv-01/certificate \
  --query SecretString --output text > cert.pem

aws secretsmanager get-secret-value \
  --secret-id /iam-ra/hosts/lnv-01/private-key \
  --query SecretString --output text > key.pem
```

## Lambda Functions

### CA Generator (`ca_generator/app.py`)

Generates self-managed CA certificate and key during rootca stack creation.

**Actions**:
- Generates EC P-256 CA key pair
- Creates self-signed CA certificate (10 year validity)
- Stores CA private key in Secrets Manager
- Stores CA certificate in SSM Parameter

### Certificate Issuer (`certificate_issuer/app.py`)

Generates and signs host certificates during host stack creation.

**Self-Managed Mode**:
- Generates EC P-256 host key pair
- Signs certificate with CA key from Secrets Manager
- Stores in Secrets Manager

**AWS PCA Mode**:
- Generates EC P-256 host key pair
- Calls ACM PCA `IssueCertificate` API
- Polls for completion using `@helper.poll_create`
- Stores in Secrets Manager

## Stack Parameters

### Root CA Stack

| Parameter | Description | Default | Required |
|-----------|-------------|---------|----------|
| `CAMode` | CA mode: `self-managed`, `pca-create`, `pca-existing` | `self-managed` | Yes |
| `PCAArn` | Existing ACM PCA ARN (required if CAMode=pca-existing) | `""` | Conditional |
| `CAValidityYears` | CA certificate validity in years | `10` | No |
| `PCAKeyAlgorithm` | Key algorithm for new PCA (pca-create only) | `EC_prime256v1` | No |
| `PCASubjectCountry` | CA subject country code (pca-create only) | `US` | No |
| `PCASubjectOrganization` | CA subject organization (pca-create only) | `IAM Roles Anywhere` | No |
| `PCASubjectCommonName` | CA subject common name (pca-create only) | `IAM Roles Anywhere Root CA` | No |
| `SSMPrefix` | SSM Parameter Store prefix | `/iam-ra` | No |

### IAM RA Stack

| Parameter | Description | Default | Required |
|-----------|-------------|---------|----------|
| `CAMode` | CA mode (must match rootca stack) | - | Yes |
| `SSMPrefix` | SSM Parameter Store prefix | `/iam-ra` | No |
| `PCAArn` | SSM Parameter for PCA ARN | `/iam-ra/pca-arn` | No |
| `CACertificate` | SSM Parameter for CA certificate | `/iam-ra/ca-certificate` | No |

### Host Stack

| Parameter | Description | Default | Required |
|-----------|-------------|---------|----------|
| `Hostname` | Host identifier (CN in certificate) | - | Yes |
| `CAMode` | "self-managed" or "aws-pca" | `self-managed` | Yes |
| `PCAArn` | ACM PCA ARN (if aws-pca mode) | `""` | Conditional |
| `SessionDuration` | IAM session duration (seconds) | `3600` | No |
| `PolicyArns` | Comma-separated managed policies | `""` | No |

## Development

### Local Testing

```bash
# Install dependencies
uv venv && source .venv/bin/activate
uv pip install -e ".[dev]"

# Run tests
pytest

# Type checking
mypy ca_generator/ certificate_issuer/
```

### SAM Validation

```bash
# Validate templates
sam validate --config-env rootca
sam validate --config-env iamra
sam validate --config-env host

# Build without deploy (useful for CI)
sam build --config-env rootca
sam build --config-env iamra
sam build --config-env host

# Preview changes
sam deploy --config-env rootca --no-execute-changeset
```

## Security

1. **CA Private Key**: Secrets Manager, master age key backup only
2. **Host Certificates**: 365 day validity, renew before expiry
3. **IAM Trust Policy**: CN condition prevents cross-host access
4. **Audit Trail**: All Secrets Manager access logged to CloudTrail

## Cost Comparison

| Mode | Fixed Cost | Per-Host Cost | Best For |
|------|------------|---------------|----------|
| `self-managed` | $0/month | ~$0.80/month | <40 hosts |
| `pca-create` | $400/month | ~$1.55/month | >40 hosts, compliance |
| `pca-existing` | (existing PCA) | ~$1.55/month | Shared PCA |

**Cost Breakdown**:
- **Secrets Manager**: ~$0.80/host/month (2 secrets: cert + key)
- **ACM PCA Certificate**: $0.75/cert (one-time per host)
- **ACM PCA**: $400/month (shared across all hosts)
- **SSM Parameters**: Free tier
- **Lambda**: Free tier

## Stack Dependencies

```
account-rootca-stack
    │
    │  (SSM Parameters: /iam-ra/ca-mode, /iam-ra/pca-arn, /iam-ra/ca-certificate)
    │
    ▼
account-iamra-stack
    │
    │  (SSM Parameters: /iam-ra/trust-anchor-arn, /iam-ra/region)
    │
    ▼
host-stack (per host)
```

## References

- [ARCHITECTURE.md](../docs/initiatives/2026-01-19-iam-roles/ARCHITECTURE.md)
- [TODO.md](../docs/initiatives/2026-01-19-iam-roles/TODO.md)
- [crhelper](https://github.com/aws-cloudformation/custom-resource-helper)
