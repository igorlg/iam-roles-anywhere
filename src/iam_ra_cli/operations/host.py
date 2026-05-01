"""Host operations - host certificate and stack deployment."""

from dataclasses import dataclass

from botocore.exceptions import ClientError, WaiterError

from iam_ra_cli.lib import crypto
from iam_ra_cli.lib.aws import AwsContext
from iam_ra_cli.lib.cfn import delete_stack, deploy_stack
from iam_ra_cli.lib.errors import (
    CACertNotFoundError,
    CAKeyNotFoundError,
    HostError,
    PCADescribeError,
    PCAGetCertError,
    PCAIssueCertError,
    PCANotActiveError,
    PCATimeoutError,
    StackDeleteError,
)
from iam_ra_cli.lib.result import Err, Ok, Result
from iam_ra_cli.lib.storage.s3 import delete_object, read_object, write_object
from iam_ra_cli.lib.templates import get_template_path
from iam_ra_cli.models import Arn
from iam_ra_cli.operations.ca import _ca_cert_s3_key, _ca_key_local_path

HOST_TEMPLATE = "host.yaml"

# End-entity template for client authentication - required by IAM Roles Anywhere
PCA_CLIENT_AUTH_TEMPLATE_ARN = (
    "arn:aws:acm-pca:::template/EndEntityClientAuthCertificate/V1"
)

# PCA KeyAlgorithm -> SigningAlgorithm mapping.
# Used when the PCA config doesn't explicitly list a signing algorithm
# (PCA always returns one, but this is a defensive fallback).
_KEY_ALGO_TO_SIGNING_ALGO: dict[str, str] = {
    "EC_prime256v1": "SHA256WITHECDSA",
    "EC_secp384r1": "SHA384WITHECDSA",
    "RSA_2048": "SHA256WITHRSA",
    "RSA_4096": "SHA256WITHRSA",
}


def _stack_name(namespace: str, hostname: str) -> str:
    return f"iam-ra-{namespace}-host-{hostname}"


def _load_template(name: str) -> str:
    path = get_template_path(name)
    return path.read_text()


def _cert_s3_key(namespace: str, hostname: str) -> str:
    return f"{namespace}/hosts/{hostname}/certificate.pem"


def _key_s3_key(namespace: str, hostname: str) -> str:
    return f"{namespace}/hosts/{hostname}/private-key.pem"


@dataclass(frozen=True, slots=True)
class HostResult:
    """Result of onboarding a host."""

    stack_name: str
    hostname: str
    certificate_secret_arn: Arn
    private_key_secret_arn: Arn


def onboard_host_self_signed(
    ctx: AwsContext,
    namespace: str,
    hostname: str,
    bucket_name: str,
    validity_days: int = 365,
    scope: str = "default",
) -> Result[HostResult, HostError]:
    """Onboard a host using self-signed CA.

    1. Load CA certificate from S3 (scoped path)
    2. Load CA private key from local storage (scoped path)
    3. Generate host certificate
    4. Upload host cert/key to S3
    5. Deploy host stack (creates Secrets Manager secrets)
    """
    stack_name = _stack_name(namespace, hostname)
    cert_s3_key = _cert_s3_key(namespace, hostname)
    key_s3_key = _key_s3_key(namespace, hostname)
    ca_cert_key = _ca_cert_s3_key(namespace, scope)
    ca_key_path = _ca_key_local_path(namespace, scope)

    # Load CA certificate from S3
    match read_object(ctx.s3, bucket_name, ca_cert_key):
        case Err(e):
            return Err(CACertNotFoundError(bucket_name, ca_cert_key))
        case Ok(ca_cert_pem):
            pass

    # Load CA private key from local storage
    if not ca_key_path.exists():
        return Err(CAKeyNotFoundError(ca_key_path))
    ca_key_pem = ca_key_path.read_text()

    # Generate host certificate
    host_keypair = crypto.generate_host_cert(
        hostname=hostname,
        ca_cert_pem=ca_cert_pem,
        ca_key_pem=ca_key_pem,
        validity_days=validity_days,
    )

    # Upload host cert and key to S3
    match write_object(ctx.s3, bucket_name, cert_s3_key, host_keypair.certificate):
        case Err(e):
            return Err(e)
        case Ok(_):
            pass

    match write_object(ctx.s3, bucket_name, key_s3_key, host_keypair.private_key):
        case Err(e):
            return Err(e)
        case Ok(_):
            pass

    # Deploy host stack
    template = _load_template(HOST_TEMPLATE)
    match deploy_stack(
        ctx.cfn,
        stack_name=stack_name,
        template_body=template,
        parameters={
            "Namespace": namespace,
            "Hostname": hostname,
            "CertificateS3Key": cert_s3_key,
            "PrivateKeyS3Key": key_s3_key,
        },
        tags={"iam-ra:namespace": namespace, "iam-ra:hostname": hostname},
    ):
        case Err() as e:
            return e
        case Ok(outputs):
            return Ok(
                HostResult(
                    stack_name=stack_name,
                    hostname=hostname,
                    certificate_secret_arn=Arn(outputs["CertificateSecretArn"]),
                    private_key_secret_arn=Arn(outputs["PrivateKeySecretArn"]),
                )
            )


def onboard_host_pca(
    ctx: AwsContext,
    namespace: str,
    hostname: str,
    pca_arn: str,
    bucket_name: str,
    validity_days: int = 365,
    scope: str = "default",
) -> Result[HostResult, HostError]:
    """Onboard a host using ACM Private CA.

    Unlike the self-signed flow, the CA's private key lives in AWS (not locally),
    so we can't sign the cert ourselves. Instead:

    1. Generate host private key + CSR locally (key stays with us)
    2. Describe the PCA - verify status=ACTIVE and discover its signing algorithm
    3. Submit the CSR to PCA via IssueCertificate
    4. Wait for issuance (async, typically a few seconds)
    5. Retrieve the signed cert via GetCertificate
    6. Upload host cert + private key to S3
    7. Deploy host CFN stack (same as self-signed flow)

    Note: The `scope` parameter is accepted for symmetry with
    onboard_host_self_signed but is not used to load CA material
    (PCA holds the CA key).
    """
    stack_name = _stack_name(namespace, hostname)
    cert_s3_key = _cert_s3_key(namespace, hostname)
    key_s3_key = _key_s3_key(namespace, hostname)

    # Step 1: Generate host key + CSR
    host_key_csr = crypto.generate_host_keypair_and_csr(hostname=hostname)

    # Step 2: Describe PCA - check status and discover signing algorithm
    try:
        describe_resp = ctx.acm_pca.describe_certificate_authority(
            CertificateAuthorityArn=pca_arn
        )
    except ClientError as e:
        return Err(PCADescribeError(pca_arn, str(e)))

    ca_info = describe_resp["CertificateAuthority"]
    ca_status = ca_info.get("Status", "UNKNOWN")
    if ca_status != "ACTIVE":
        return Err(PCANotActiveError(pca_arn, ca_status))

    ca_config = ca_info["CertificateAuthorityConfiguration"]
    signing_algorithm = ca_config.get("SigningAlgorithm") or _KEY_ALGO_TO_SIGNING_ALGO.get(
        ca_config.get("KeyAlgorithm", ""), "SHA256WITHECDSA"
    )

    # Step 3: Submit CSR to PCA
    try:
        issue_resp = ctx.acm_pca.issue_certificate(
            CertificateAuthorityArn=pca_arn,
            Csr=host_key_csr.csr_pem.encode(),
            SigningAlgorithm=signing_algorithm,
            TemplateArn=PCA_CLIENT_AUTH_TEMPLATE_ARN,
            Validity={"Value": validity_days, "Type": "DAYS"},
        )
    except ClientError as e:
        return Err(PCAIssueCertError(pca_arn, str(e)))

    certificate_arn = issue_resp["CertificateArn"]

    # Step 4: Wait for issuance
    try:
        waiter = ctx.acm_pca.get_waiter("certificate_issued")
        waiter.wait(
            CertificateAuthorityArn=pca_arn,
            CertificateArn=certificate_arn,
            WaiterConfig={"Delay": 2, "MaxAttempts": 30},
        )
    except WaiterError:
        return Err(PCATimeoutError(pca_arn, certificate_arn))

    # Step 5: Retrieve signed certificate
    try:
        cert_resp = ctx.acm_pca.get_certificate(
            CertificateAuthorityArn=pca_arn,
            CertificateArn=certificate_arn,
        )
    except ClientError as e:
        return Err(PCAGetCertError(pca_arn, certificate_arn, str(e)))

    host_cert_pem = cert_resp["Certificate"]

    # Step 6: Upload host cert and private key to S3
    match write_object(ctx.s3, bucket_name, cert_s3_key, host_cert_pem):
        case Err(e):
            return Err(e)
        case Ok(_):
            pass

    match write_object(ctx.s3, bucket_name, key_s3_key, host_key_csr.private_key_pem):
        case Err(e):
            return Err(e)
        case Ok(_):
            pass

    # Step 7: Deploy host stack (same as self-signed flow)
    template = _load_template(HOST_TEMPLATE)
    match deploy_stack(
        ctx.cfn,
        stack_name=stack_name,
        template_body=template,
        parameters={
            "Namespace": namespace,
            "Hostname": hostname,
            "CertificateS3Key": cert_s3_key,
            "PrivateKeyS3Key": key_s3_key,
        },
        tags={"iam-ra:namespace": namespace, "iam-ra:hostname": hostname},
    ):
        case Err() as e:
            return e
        case Ok(outputs):
            return Ok(
                HostResult(
                    stack_name=stack_name,
                    hostname=hostname,
                    certificate_secret_arn=Arn(outputs["CertificateSecretArn"]),
                    private_key_secret_arn=Arn(outputs["PrivateKeySecretArn"]),
                )
            )


def offboard_host(
    ctx: AwsContext,
    stack_name: str,
    bucket_name: str,
    namespace: str,
    hostname: str,
) -> Result[None, StackDeleteError]:
    """Offboard a host - delete stack and cleanup S3.

    1. Delete host stack (deletes Secrets Manager secrets)
    2. Delete host cert/key from S3
    """
    # Delete stack first
    match delete_stack(ctx.cfn, stack_name):
        case Err() as e:
            return e
        case Ok(_):
            pass

    # Cleanup S3 (best effort - ignore errors)
    cert_s3_key = _cert_s3_key(namespace, hostname)
    key_s3_key = _key_s3_key(namespace, hostname)
    delete_object(ctx.s3, bucket_name, cert_s3_key)
    delete_object(ctx.s3, bucket_name, key_s3_key)

    return Ok(None)
