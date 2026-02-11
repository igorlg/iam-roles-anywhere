# Kubernetes Examples

This directory contains example Kubernetes manifests for IAM Roles Anywhere integration.

## Examples

| Example | Description |
|---------|-------------|
| [`single-workload/`](single-workload/) | Single workload with one role |
| [`multi-workload/`](multi-workload/) | Multiple workloads with different roles |
| [`custom-namespace/`](custom-namespace/) | Workloads in custom K8s namespaces |

## Prerequisites

1. Initialize IAM-RA with self-signed CA:
   ```bash
   iam-ra init --ca-mode self-signed
   ```

2. Create roles:
   ```bash
   iam-ra role create admin --policy arn:aws:iam::aws:policy/AdministratorAccess
   iam-ra role create readonly --policy arn:aws:iam::aws:policy/ReadOnlyAccess
   ```

3. Install cert-manager in your cluster:
   ```bash
   kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.14.0/cert-manager.yaml
   ```

## Usage

### Quick Start (generates all manifests)

```bash
# Set up cluster
iam-ra k8s setup prod | kubectl apply -f -

# Onboard workload
iam-ra k8s onboard my-app --role admin --cluster prod | kubectl apply -f -

# Verify
kubectl logs my-app-sample -c app
```

### Using the Examples

Copy and customize the examples for your environment:

```bash
# Copy an example
cp -r examples/k8s/single-workload/ my-k8s-config/

# Update the ARNs in the ConfigMap
vim my-k8s-config/workload.yaml

# Apply
kubectl apply -f my-k8s-config/
```

## Directory Structure

Each example contains:

```
example/
├── cluster.yaml      # CA Secret + Issuer (once per cluster)
└── workload.yaml     # Certificate + ConfigMap + Pod (per workload)
```

## Notes

- The `cluster.yaml` needs your actual CA certificate from `iam-ra`
- The `workload.yaml` needs ARNs from `iam-ra status --json`
- Sample pods are for testing; replace with your Deployment/StatefulSet
