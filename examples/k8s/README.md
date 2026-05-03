# Kubernetes Examples

This directory contains resources for integrating IAM Roles Anywhere with
Kubernetes workloads via cert-manager.

For the full integration guide, see
[`docs/KUBERNETES.md`](../../docs/KUBERNETES.md).

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

## Quick start

The CLI generates all manifests; no manual YAML required for the common
paths.

```bash
# Set up cluster (once per cluster): CA Secret + Issuer
iam-ra k8s setup prod | kubectl apply -f -

# Onboard a workload (per workload): Certificate + ConfigMap + Pod
iam-ra k8s onboard my-app --role admin --cluster prod | kubectl apply -f -

# Verify
kubectl logs my-app-sample -c app
```

## Customisation

Pipe the generated manifests into a file instead of `kubectl apply` to
edit before applying:

```bash
iam-ra k8s onboard my-app --role admin --cluster prod > my-app.yaml
vim my-app.yaml
kubectl apply -f my-app.yaml
```

## Notes

- Sample pods are for testing; replace with your Deployment/StatefulSet.
- `iam-ra status --json` exposes all the ARNs and identifiers you need
  for manual manifests.
