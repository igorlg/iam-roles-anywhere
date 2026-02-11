# Kubernetes Integration

This guide explains how to use IAM Roles Anywhere with Kubernetes clusters using cert-manager for certificate management.

## Overview

IAM Roles Anywhere enables workloads outside of AWS to obtain temporary AWS credentials using X.509 certificates. For Kubernetes, this means pods can authenticate to AWS without needing IRSA (IAM Roles for Service Accounts) or long-lived credentials.

### Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         Kubernetes Cluster                                │
│                                                                          │
│  ┌─────────────────┐    ┌──────────────────────────────────────────────┐ │
│  │   cert-manager  │    │                   Pod                        │ │
│  │                 │    │  ┌────────────┐    ┌───────────────────────┐ │ │
│  │  Issues certs   │───►│  │    App     │    │   IAM-RA Sidecar      │ │ │
│  │  from CA        │    │  │ Container  │◄──►│   (aws_signing_helper)│ │ │
│  └─────────────────┘    │  │            │    │                       │ │ │
│          │              │  │ AWS SDK    │    │  Reads cert, signs    │ │ │
│          │              │  │ calls      │    │  requests, returns    │ │ │
│          │              │  │ localhost  │    │  credentials          │ │ │
│          │              │  └────────────┘    └───────────────────────┘ │ │
│          │              │                             ▲                 │ │
│          │              │                             │                 │ │
│          │              │         Volume: Certificate Secret           │ │
│          │              └──────────────────────────────────────────────┘ │
│          │                                                               │
│          ▼                                                               │
│  ┌─────────────────┐                                                     │
│  │   CA Secret     │   Contains self-signed CA cert from iam-ra         │
│  │   (K8s Secret)  │                                                     │
│  └─────────────────┘                                                     │
└──────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ HTTPS (signed by CA)
                                    ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                              AWS                                         │
│                                                                          │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐      │
│  │  Trust Anchor   │───►│  IAM RA Profile │───►│    IAM Role     │      │
│  │  (trusts CA)    │    │                 │    │                 │      │
│  └─────────────────┘    └─────────────────┘    └─────────────────┘      │
└──────────────────────────────────────────────────────────────────────────┘
```

### Key Benefits

- **No IRSA required** - Works with any K8s cluster (on-prem, self-managed, EKS)
- **No OIDC endpoint needed** - Avoids OIDC provider limits and complexity
- **Short-lived credentials** - Certificates and AWS credentials auto-rotate
- **Fine-grained access** - Different pods can assume different IAM roles

## Prerequisites

1. **IAM-RA initialized** with self-signed CA mode:
   ```bash
   iam-ra init --ca-mode self-signed
   ```

2. **At least one role created**:
   ```bash
   iam-ra role create admin --policy arn:aws:iam::aws:policy/AdministratorAccess
   ```

3. **cert-manager installed** in your cluster:
   ```bash
   kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.14.0/cert-manager.yaml
   ```

## Quick Start

### 1. Set Up the Cluster

Run once per Kubernetes cluster to create the CA Secret and cert-manager Issuer:

```bash
# Generate and apply cluster-level manifests
iam-ra k8s setup prod-cluster | kubectl apply -f -
```

This creates:
- `iam-ra-ca` Secret containing your CA certificate
- `iam-ra` Issuer that cert-manager uses to sign certificates

### 2. Onboard a Workload

For each application that needs AWS credentials:

```bash
# Generate and apply workload-level manifests
iam-ra k8s onboard payment-service --role admin --cluster prod-cluster | kubectl apply -f -
```

This creates:
- `payment-service-cert` Certificate (cert-manager will issue it)
- `payment-service-iam-ra-config` ConfigMap with ARNs
- `payment-service-sample` Pod (sample, replace with your deployment)

### 3. Verify It Works

```bash
# Check the sample pod
kubectl logs payment-service-sample -c app

# Should show output like:
# {
#     "UserId": "AROA...:payment-service",
#     "Account": "123456789012",
#     "Arn": "arn:aws:sts::123456789012:assumed-role/admin/payment-service"
# }
```

## CLI Commands Reference

### Cluster Management

```bash
# Set up a cluster (generate CA secret + Issuer)
iam-ra k8s setup <cluster-name> [--k8s-namespace <ns>]

# Remove cluster from state (doesn't touch K8s)
iam-ra k8s teardown <cluster-name>

# List all clusters and workloads
iam-ra k8s list [--cluster <name>] [--json]
```

### Workload Management

```bash
# Onboard a workload (generate Certificate + ConfigMap + Pod)
iam-ra k8s onboard <workload-name> \
  --role <role-name> \
  --cluster <cluster-name> \
  [--k8s-namespace <ns>] \
  [--duration-hours <hours>]

# Remove workload from state (doesn't touch K8s)
iam-ra k8s offboard <workload-name>
```

## Understanding the Generated Manifests

### CA Secret (`iam-ra-ca`)

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: iam-ra-ca
  namespace: default
type: kubernetes.io/tls
stringData:
  tls.crt: |
    -----BEGIN CERTIFICATE-----
    ... your CA certificate ...
    -----END CERTIFICATE-----
  tls.key: ""
```

This secret contains the CA certificate that your IAM-RA Trust Anchor trusts. cert-manager's Issuer references this to sign pod certificates.

### Issuer (`iam-ra`)

```yaml
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: iam-ra
  namespace: default
spec:
  ca:
    secretName: iam-ra-ca
```

The Issuer tells cert-manager how to sign Certificate requests.

### Certificate (`<workload>-cert`)

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: payment-service-cert
  namespace: default
spec:
  commonName: "payment-service"
  duration: 24h0m0s
  renewBefore: 5m0s
  secretName: payment-service-cert
  privateKey:
    algorithm: RSA
    size: 2048
  issuerRef:
    kind: Issuer
    name: iam-ra
```

cert-manager creates a K8s Secret with `tls.crt` and `tls.key` containing the pod's certificate and private key. It automatically renews before expiry.

### ConfigMap (`<workload>-iam-ra-config`)

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: payment-service-iam-ra-config
data:
  TRUST_ANCHOR_ARN: "arn:aws:rolesanywhere:..."
  PROFILE_ARN: "arn:aws:rolesanywhere:..."
  ROLE_ARN: "arn:aws:iam::...:role/admin"
```

Contains the ARNs needed by the sidecar to obtain credentials.

### Sample Pod

The generated pod shows the sidecar pattern:

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
    # Your application container
    - name: app
      env:
        - name: AWS_EC2_METADATA_SERVICE_ENDPOINT
          value: "http://127.0.0.1:9911/"
    
    # IAM-RA sidecar
    - name: iam-ra-sidecar
      image: public.ecr.aws/rolesanywhere/aws-signing-helper:latest
      args:
        - credential-process
        - "--certificate"
        - "/var/run/secrets/iam-ra/tls.crt"
        - "--private-key"
        - "/var/run/secrets/iam-ra/tls.key"
        - "--trust-anchor-arn"
        - "$(TRUST_ANCHOR_ARN)"
        - "--profile-arn"
        - "$(PROFILE_ARN)"
        - "--role-arn"
        - "$(ROLE_ARN)"
      volumeMounts:
        - name: iam-ra-cert
          mountPath: /var/run/secrets/iam-ra
          readOnly: true
  
  volumes:
    - name: iam-ra-cert
      secret:
        secretName: payment-service-cert
```

## Integrating with Your Deployments

The sample pod is just a template. For real workloads, add the sidecar to your Deployment/StatefulSet:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  template:
    spec:
      containers:
        - name: my-app
          image: my-app:latest
          env:
            # Point AWS SDK to the sidecar
            - name: AWS_EC2_METADATA_SERVICE_ENDPOINT
              value: "http://127.0.0.1:9911/"
        
        # Add the sidecar
        - name: iam-ra-sidecar
          image: public.ecr.aws/rolesanywhere/aws-signing-helper:latest
          # ... (same as sample pod)
      
      volumes:
        - name: iam-ra-cert
          secret:
            secretName: my-app-cert
```

## Multiple Roles

Different workloads can assume different roles:

```bash
# Create roles
iam-ra role create admin --policy arn:aws:iam::aws:policy/AdministratorAccess
iam-ra role create readonly --policy arn:aws:iam::aws:policy/ReadOnlyAccess

# Onboard workloads with different roles
iam-ra k8s onboard backend-api --role admin --cluster prod
iam-ra k8s onboard monitoring --role readonly --cluster prod
```

## Multiple Clusters

Track multiple clusters in one namespace:

```bash
# Set up different clusters
iam-ra k8s setup prod-us-east-1
iam-ra k8s setup prod-eu-west-1
iam-ra k8s setup staging

# List all
iam-ra k8s list
```

## Security Considerations

1. **Certificate Duration**: Default is 24 hours. cert-manager renews 5 minutes before expiry. Adjust with `--duration-hours`.

2. **Namespace Isolation**: Consider using separate K8s namespaces for different security boundaries:
   ```bash
   iam-ra k8s setup prod --k8s-namespace iam-ra-system
   iam-ra k8s onboard api --cluster prod --k8s-namespace api-ns
   ```

3. **Sidecar Security**: The generated sidecar runs as non-root with read-only filesystem.

4. **Credential Scope**: Each workload gets its own certificate. Compromised credentials only affect that workload.

## Troubleshooting

### Certificate not issued

Check cert-manager logs and Certificate status:
```bash
kubectl describe certificate payment-service-cert
kubectl logs -n cert-manager deploy/cert-manager
```

### Credentials not working

Check the sidecar logs:
```bash
kubectl logs payment-service-sample -c iam-ra-sidecar
```

Verify the Trust Anchor trusts your CA:
```bash
aws rolesanywhere get-trust-anchor --trust-anchor-id <id>
```

### "CA mode not supported"

K8s integration only works with self-signed CA mode. Re-initialize:
```bash
iam-ra destroy --yes
iam-ra init --ca-mode self-signed
```

## Comparison with IRSA

| Feature | IRSA | IAM Roles Anywhere |
|---------|------|-------------------|
| Works with EKS | Yes | Yes |
| Works with self-managed K8s | No | Yes |
| Works on-premises | No | Yes |
| Requires OIDC provider | Yes | No |
| Trust policy limit (4KB) | Can hit limit | No limit |
| Session tags | No | Yes |
| Certificate rotation | N/A | Automatic (cert-manager) |

Use IAM Roles Anywhere when:
- You have on-prem or self-managed K8s clusters
- You need to avoid OIDC complexity
- You want session tags for fine-grained access control
- You're hitting OIDC provider limits
