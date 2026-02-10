"""Host operations - host certificate and stack deployment."""

from dataclasses import dataclass
from pathlib import Path

from iam_ra_cli.lib import crypto, paths
from iam_ra_cli.lib.aws import AwsContext
from iam_ra_cli.lib.cfn import delete_stack, deploy_stack
from iam_ra_cli.lib.errors import (
    CACertNotFoundError,
    CAKeyNotFoundError,
    HostError,
    StackDeleteError,
    StackDeployError,
)
from iam_ra_cli.lib.result import Err, Ok, Result
from iam_ra_cli.lib.storage.s3 import delete_object, read_object, write_object
from iam_ra_cli.lib.templates import get_template_path
from iam_ra_cli.models import Arn

HOST_TEMPLATE = "host.yaml"


def _stack_name(namespace: str, hostname: str) -> str:
    return f"iam-ra-{namespace}-host-{hostname}"


def _load_template(name: str) -> str:
    path = get_template_path(name)
    return path.read_text()


def _cert_s3_key(namespace: str, hostname: str) -> str:
    return f"{namespace}/hosts/{hostname}/certificate.pem"


def _key_s3_key(namespace: str, hostname: str) -> str:
    return f"{namespace}/hosts/{hostname}/private-key.pem"


def _ca_cert_s3_key(namespace: str) -> str:
    return f"{namespace}/ca/certificate.pem"


def _ca_key_local_path(namespace: str) -> Path:
    return paths.data_dir() / namespace / "ca-private-key.pem"


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
) -> Result[HostResult, HostError]:
    """Onboard a host using self-signed CA.

    1. Load CA certificate from S3
    2. Load CA private key from local storage
    3. Generate host certificate
    4. Upload host cert/key to S3
    5. Deploy host stack (creates Secrets Manager secrets)
    """
    stack_name = _stack_name(namespace, hostname)
    cert_s3_key = _cert_s3_key(namespace, hostname)
    key_s3_key = _key_s3_key(namespace, hostname)
    ca_cert_key = _ca_cert_s3_key(namespace)
    ca_key_path = _ca_key_local_path(namespace)

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
) -> Result[HostResult, StackDeployError]:
    """Onboard a host using ACM PCA.

    TODO: Implement PCA certificate issuance.
    """
    # For now, raise not implemented
    return Err(
        StackDeployError("", "NOT_IMPLEMENTED", "PCA certificate issuance not yet implemented")
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
