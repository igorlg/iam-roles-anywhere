"""CA operations - Certificate Authority stack deployment."""

from dataclasses import dataclass
from pathlib import Path

from iam_ra_cli.lib import crypto, paths
from iam_ra_cli.lib.aws import AwsContext
from iam_ra_cli.lib.cfn import delete_stack, deploy_stack
from iam_ra_cli.lib.errors import (
    CAError,
    CACertNotFoundError,
    CAKeyNotFoundError,
    S3WriteError,
    StackDeleteError,
    StackDeployError,
)
from iam_ra_cli.lib.result import Err, Ok, Result
from iam_ra_cli.lib.storage.s3 import write_object
from iam_ra_cli.lib.templates import get_template_path
from iam_ra_cli.models import Arn

ROOTCA_SELF_SIGNED_TEMPLATE = "rootca-self-signed.yaml"
ROOTCA_PCA_NEW_TEMPLATE = "rootca-pca-new.yaml"
ROOTCA_PCA_EXISTING_TEMPLATE = "rootca-pca-existing.yaml"


def _stack_name(namespace: str) -> str:
    return f"iam-ra-{namespace}-rootca"


def _load_template(name: str) -> str:
    path = get_template_path(name)
    return path.read_text()


def _ca_cert_s3_key(namespace: str) -> str:
    return f"{namespace}/ca/certificate.pem"


def _ca_key_local_path(namespace: str) -> Path:
    return paths.data_dir() / namespace / "ca-private-key.pem"


@dataclass(frozen=True, slots=True)
class SelfSignedCAResult:
    """Result of creating self-signed CA."""

    stack_name: str
    trust_anchor_arn: Arn
    cert_s3_key: str
    local_key_path: Path


@dataclass(frozen=True, slots=True)
class PCAResult:
    """Result of creating/attaching PCA."""

    stack_name: str
    trust_anchor_arn: Arn
    pca_arn: Arn


def create_self_signed_ca(
    ctx: AwsContext,
    namespace: str,
    bucket_name: str,
    validity_years: int = 10,
) -> Result[SelfSignedCAResult, CAError]:
    """Create a self-signed CA and deploy the rootca stack.

    1. Generate CA certificate and private key locally
    2. Upload CA certificate to S3
    3. Save CA private key locally (for future host cert generation)
    4. Deploy rootca-self-signed.yaml stack
    """
    stack_name = _stack_name(namespace)
    cert_s3_key = _ca_cert_s3_key(namespace)
    local_key_path = _ca_key_local_path(namespace)

    # Generate CA certificate and key
    ca_keypair = crypto.generate_ca(
        common_name=f"IAM Roles Anywhere CA ({namespace})",
        validity_years=validity_years,
    )

    # Upload CA certificate to S3
    match write_object(ctx.s3, bucket_name, cert_s3_key, ca_keypair.certificate):
        case Err(e):
            return Err(e)
        case Ok(_):
            pass

    # Save CA private key locally
    local_key_path.parent.mkdir(parents=True, exist_ok=True)
    local_key_path.write_text(ca_keypair.private_key)
    local_key_path.chmod(0o600)

    # Deploy rootca stack
    template = _load_template(ROOTCA_SELF_SIGNED_TEMPLATE)
    match deploy_stack(
        ctx.cfn,
        stack_name=stack_name,
        template_body=template,
        parameters={
            "Namespace": namespace,
            "CACertificateS3Key": cert_s3_key,
        },
        tags={"iam-ra:namespace": namespace},
    ):
        case Err() as e:
            return e
        case Ok(outputs):
            return Ok(
                SelfSignedCAResult(
                    stack_name=stack_name,
                    trust_anchor_arn=Arn(outputs["TrustAnchorArn"]),
                    cert_s3_key=cert_s3_key,
                    local_key_path=local_key_path,
                )
            )


def create_pca_ca(
    ctx: AwsContext,
    namespace: str,
    key_algorithm: str = "EC_prime256v1",
    validity_years: int = 10,
) -> Result[PCAResult, StackDeployError]:
    """Create a new ACM PCA and deploy the rootca stack."""
    stack_name = _stack_name(namespace)
    template = _load_template(ROOTCA_PCA_NEW_TEMPLATE)

    match deploy_stack(
        ctx.cfn,
        stack_name=stack_name,
        template_body=template,
        parameters={
            "Namespace": namespace,
            "KeyAlgorithm": key_algorithm,
            "ValidityYears": str(validity_years),
        },
        tags={"iam-ra:namespace": namespace},
    ):
        case Err() as e:
            return e
        case Ok(outputs):
            return Ok(
                PCAResult(
                    stack_name=stack_name,
                    trust_anchor_arn=Arn(outputs["TrustAnchorArn"]),
                    pca_arn=Arn(outputs["PCAArn"]),
                )
            )


def attach_existing_pca(
    ctx: AwsContext,
    namespace: str,
    pca_arn: str,
) -> Result[PCAResult, StackDeployError]:
    """Attach an existing ACM PCA and deploy the rootca stack."""
    stack_name = _stack_name(namespace)
    template = _load_template(ROOTCA_PCA_EXISTING_TEMPLATE)

    match deploy_stack(
        ctx.cfn,
        stack_name=stack_name,
        template_body=template,
        parameters={
            "Namespace": namespace,
            "PCAArn": pca_arn,
        },
        tags={"iam-ra:namespace": namespace},
    ):
        case Err() as e:
            return e
        case Ok(outputs):
            return Ok(
                PCAResult(
                    stack_name=stack_name,
                    trust_anchor_arn=Arn(outputs["TrustAnchorArn"]),
                    pca_arn=Arn(outputs["PCAArn"]),
                )
            )


def delete_ca(ctx: AwsContext, stack_name: str) -> Result[None, StackDeleteError]:
    """Delete the CA stack."""
    return delete_stack(ctx.cfn, stack_name)
