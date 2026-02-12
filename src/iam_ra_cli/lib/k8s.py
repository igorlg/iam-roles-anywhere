"""Kubernetes manifest generation for IAM Roles Anywhere.

Generates cert-manager and pod manifests for K8s integration.
All functions are pure - they generate YAML strings from inputs.
"""

from dataclasses import dataclass

# Default values for manifest generation
DEFAULT_CERT_DURATION_HOURS = 24
DEFAULT_CERT_RENEW_BEFORE_MINUTES = 5
DEFAULT_ISSUER_NAME = "iam-ra"
DEFAULT_CA_SECRET_NAME = "iam-ra-ca"
DEFAULT_CERT_SECRET_NAME = "iam-ra-cert"

# Public ECR image for aws_signing_helper
# Users can override this if they want to use their own image
AWS_SIGNING_HELPER_IMAGE = "public.ecr.aws/rolesanywhere/aws-signing-helper:latest"


@dataclass(frozen=True)
class ClusterManifests:
    """Cluster-level K8s manifests (CA Secret + Issuer)."""

    ca_secret: str
    issuer: str

    def to_yaml(self) -> str:
        """Return combined YAML with document separator."""
        return f"{self.ca_secret}---\n{self.issuer}"


@dataclass(frozen=True)
class WorkloadManifests:
    """Workload-level K8s manifests (Certificate + ConfigMap + optional sample Pod)."""

    certificate: str
    configmap: str
    pod: str | None = None

    def to_yaml(self) -> str:
        """Return combined YAML with document separator."""
        parts = [self.certificate, self.configmap]
        if self.pod is not None:
            parts.append(self.pod)
        return "---\n".join(parts)


def generate_ca_secret(
    ca_cert_pem: str,
    ca_key_pem: str,
    name: str = DEFAULT_CA_SECRET_NAME,
    namespace: str = "default",
) -> str:
    """Generate K8s Secret containing CA certificate for cert-manager.

    This secret is referenced by the cert-manager Issuer to sign certificates.
    For self-signed CA mode only.

    Args:
        ca_cert_pem: CA certificate in PEM format
        ca_key_pem: CA private key in PEM format
        name: Secret name
        namespace: K8s namespace

    Returns:
        YAML manifest for the Secret
    """
    # Indent the cert and key for YAML
    indented_cert = "\n".join(f"    {line}" for line in ca_cert_pem.strip().split("\n"))
    indented_key = "\n".join(f"    {line}" for line in ca_key_pem.strip().split("\n"))

    return f"""apiVersion: v1
kind: Secret
metadata:
  name: {name}
  namespace: {namespace}
type: kubernetes.io/tls
stringData:
  tls.crt: |
{indented_cert}
  tls.key: |
{indented_key}
"""


def generate_issuer(
    name: str = DEFAULT_ISSUER_NAME,
    namespace: str = "default",
    ca_secret_name: str = DEFAULT_CA_SECRET_NAME,
) -> str:
    """Generate cert-manager Issuer manifest.

    The Issuer references the CA Secret and is used to sign Certificate requests.

    Args:
        name: Issuer name
        namespace: K8s namespace
        ca_secret_name: Name of the Secret containing CA cert

    Returns:
        YAML manifest for the Issuer
    """
    return f"""apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: {name}
  namespace: {namespace}
spec:
  ca:
    secretName: {ca_secret_name}
"""


def generate_certificate(
    workload_name: str,
    namespace: str = "default",
    issuer_name: str = DEFAULT_ISSUER_NAME,
    secret_name: str | None = None,
    duration_hours: int = DEFAULT_CERT_DURATION_HOURS,
    renew_before_minutes: int = DEFAULT_CERT_RENEW_BEFORE_MINUTES,
    common_name: str | None = None,
) -> str:
    """Generate cert-manager Certificate manifest.

    The Certificate requests a short-lived cert from the Issuer.
    cert-manager handles automatic renewal.

    Args:
        workload_name: Name of the workload (used in cert naming)
        namespace: K8s namespace
        issuer_name: Name of the Issuer to use
        secret_name: Name for the generated Secret (default: {workload_name}-cert)
        duration_hours: Certificate validity in hours
        renew_before_minutes: Renew this many minutes before expiry
        common_name: Certificate CN (default: workload_name)

    Returns:
        YAML manifest for the Certificate
    """
    if secret_name is None:
        secret_name = f"{workload_name}-cert"
    if common_name is None:
        common_name = workload_name

    return f"""apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: {workload_name}-cert
  namespace: {namespace}
spec:
  commonName: "{common_name}"
  duration: {duration_hours}h0m0s
  renewBefore: {renew_before_minutes}m0s
  secretName: {secret_name}
  privateKey:
    algorithm: RSA
    size: 2048
  issuerRef:
    group: cert-manager.io
    kind: Issuer
    name: {issuer_name}
"""


def generate_configmap(
    workload_name: str,
    trust_anchor_arn: str,
    profile_arn: str,
    role_arn: str,
    namespace: str = "default",
) -> str:
    """Generate ConfigMap with IAM Roles Anywhere ARNs.

    The sidecar container reads these ARNs from the ConfigMap.

    Args:
        workload_name: Name of the workload
        trust_anchor_arn: IAM Roles Anywhere Trust Anchor ARN
        profile_arn: IAM Roles Anywhere Profile ARN
        role_arn: IAM Role ARN to assume
        namespace: K8s namespace

    Returns:
        YAML manifest for the ConfigMap
    """
    return f"""apiVersion: v1
kind: ConfigMap
metadata:
  name: {workload_name}-iam-ra-config
  namespace: {namespace}
data:
  TRUST_ANCHOR_ARN: "{trust_anchor_arn}"
  PROFILE_ARN: "{profile_arn}"
  ROLE_ARN: "{role_arn}"
"""


def generate_sample_pod(
    workload_name: str,
    namespace: str = "default",
    cert_secret_name: str | None = None,
    signing_helper_image: str = AWS_SIGNING_HELPER_IMAGE,
) -> str:
    """Generate sample Pod manifest with aws_signing_helper sidecar.

    This is a sample/template showing how to configure a pod to use
    IAM Roles Anywhere credentials via the sidecar pattern.

    The sidecar runs aws_signing_helper in "serve" mode, exposing an
    IMDS-compatible endpoint on localhost:9911. Application containers
    use this via AWS_EC2_METADATA_SERVICE_ENDPOINT.

    Args:
        workload_name: Name of the workload
        namespace: K8s namespace
        cert_secret_name: Name of the cert Secret (default: {workload_name}-cert)
        signing_helper_image: Container image for aws_signing_helper

    Returns:
        YAML manifest for the sample Pod
    """
    if cert_secret_name is None:
        cert_secret_name = f"{workload_name}-cert"

    configmap_name = f"{workload_name}-iam-ra-config"

    return f"""apiVersion: v1
kind: Pod
metadata:
  name: {workload_name}-sample
  namespace: {namespace}
  labels:
    app: {workload_name}
spec:
  containers:
    # ======================
    # APPLICATION CONTAINER
    # ======================
    # Replace this with your actual application container.
    # The only requirement is setting AWS_EC2_METADATA_SERVICE_ENDPOINT
    # to point to the sidecar.
    - name: app
      image: public.ecr.aws/aws-cli/aws-cli:latest
      command: ["sh", "-c"]
      args:
        - |
          echo "Testing IAM Roles Anywhere credentials..."
          aws sts get-caller-identity
          echo "Credentials working! Sleeping..."
          sleep 3600
      env:
        - name: AWS_EC2_METADATA_SERVICE_ENDPOINT
          value: "http://127.0.0.1:9911/"
      resources:
        requests:
          memory: "64Mi"
          cpu: "100m"
        limits:
          memory: "128Mi"
          cpu: "200m"

    # ======================
    # IAM-RA SIDECAR
    # ======================
    # This sidecar provides AWS credentials to all containers in the pod.
    # It runs aws_signing_helper in "serve" mode, emulating IMDS.
    - name: iam-ra-sidecar
      image: {signing_helper_image}
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
      env:
        - name: TRUST_ANCHOR_ARN
          valueFrom:
            configMapKeyRef:
              name: {configmap_name}
              key: TRUST_ANCHOR_ARN
        - name: PROFILE_ARN
          valueFrom:
            configMapKeyRef:
              name: {configmap_name}
              key: PROFILE_ARN
        - name: ROLE_ARN
          valueFrom:
            configMapKeyRef:
              name: {configmap_name}
              key: ROLE_ARN
      volumeMounts:
        - name: iam-ra-cert
          mountPath: /var/run/secrets/iam-ra
          readOnly: true
      resources:
        requests:
          memory: "32Mi"
          cpu: "50m"
        limits:
          memory: "64Mi"
          cpu: "100m"
      securityContext:
        runAsNonRoot: true
        runAsUser: 65534
        readOnlyRootFilesystem: true
        allowPrivilegeEscalation: false

  volumes:
    - name: iam-ra-cert
      secret:
        secretName: {cert_secret_name}
"""


def generate_cluster_manifests(
    ca_cert_pem: str,
    ca_key_pem: str,
    namespace: str = "default",
    ca_secret_name: str = DEFAULT_CA_SECRET_NAME,
    issuer_name: str = DEFAULT_ISSUER_NAME,
) -> ClusterManifests:
    """Generate all cluster-level manifests.

    Args:
        ca_cert_pem: CA certificate in PEM format
        ca_key_pem: CA private key in PEM format
        namespace: K8s namespace for the CA secret and issuer
        ca_secret_name: Name for the CA secret
        issuer_name: Name for the Issuer

    Returns:
        ClusterManifests with ca_secret and issuer YAML
    """
    return ClusterManifests(
        ca_secret=generate_ca_secret(ca_cert_pem, ca_key_pem, ca_secret_name, namespace),
        issuer=generate_issuer(issuer_name, namespace, ca_secret_name),
    )


def generate_workload_manifests(
    workload_name: str,
    trust_anchor_arn: str,
    profile_arn: str,
    role_arn: str,
    namespace: str = "default",
    issuer_name: str = DEFAULT_ISSUER_NAME,
    duration_hours: int = DEFAULT_CERT_DURATION_HOURS,
    include_sample_pod: bool = True,
) -> WorkloadManifests:
    """Generate all workload-level manifests.

    Args:
        workload_name: Name of the workload
        trust_anchor_arn: IAM Roles Anywhere Trust Anchor ARN
        profile_arn: IAM Roles Anywhere Profile ARN
        role_arn: IAM Role ARN to assume
        namespace: K8s namespace
        issuer_name: Name of the Issuer to reference
        duration_hours: Certificate validity in hours
        include_sample_pod: Whether to include the sample Pod manifest

    Returns:
        WorkloadManifests with certificate, configmap, and optionally pod YAML
    """
    cert_secret_name = f"{workload_name}-cert"

    pod = None
    if include_sample_pod:
        pod = generate_sample_pod(
            workload_name=workload_name,
            namespace=namespace,
            cert_secret_name=cert_secret_name,
        )

    return WorkloadManifests(
        certificate=generate_certificate(
            workload_name=workload_name,
            namespace=namespace,
            issuer_name=issuer_name,
            secret_name=cert_secret_name,
            duration_hours=duration_hours,
        ),
        configmap=generate_configmap(
            workload_name=workload_name,
            trust_anchor_arn=trust_anchor_arn,
            profile_arn=profile_arn,
            role_arn=role_arn,
            namespace=namespace,
        ),
        pod=pod,
    )
