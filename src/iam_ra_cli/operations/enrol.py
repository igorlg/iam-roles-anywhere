"""Certificate issuance from an externally-supplied CSR.

This is the v3 counterpart to :mod:`iam_ra_cli.operations.host`. The difference
is the whole point of v3: the CSR arrives from outside this process - generated
on the host that will use the certificate - and only a **certificate** comes
back. No private key is generated, transmitted, uploaded or stored here.
"""

from iam_ra_cli.lib import crypto
from iam_ra_cli.lib.aws import AwsContext
from iam_ra_cli.lib.errors import (
    CACertNotFoundError,
    CAKeyNotFoundError,
    CsrInvalidSignatureError,
    CsrParseError,
    CsrSubjectMismatchError,
    CsrUnsupportedKeyError,
    PCADescribeError,
    PCAGetCertError,
    PCAIssueCertError,
    PCANotActiveError,
    PCATimeoutError,
    S3ReadError,
)
from iam_ra_cli.lib.result import Err, Ok, Result
from iam_ra_cli.lib.storage.s3 import read_object
from iam_ra_cli.models import CA, CAMode

type SignHostCsrError = (
    CsrParseError
    | CsrInvalidSignatureError
    | CsrUnsupportedKeyError
    | CsrSubjectMismatchError
    | CACertNotFoundError
    | CAKeyNotFoundError
    | S3ReadError
    | PCADescribeError
    | PCANotActiveError
    | PCAIssueCertError
    | PCATimeoutError
    | PCAGetCertError
)


def sign_host_csr(
    ctx: AwsContext,
    namespace: str,
    hostname: str,
    scope: str,
    scope_ca: CA,
    bucket_name: str,
    csr_pem: str,
    validity_days: int = 365,
) -> Result[str, SignHostCsrError]:
    """Issue a client-auth certificate for ``hostname`` from ``csr_pem``.

    Returns the certificate PEM. Nothing is uploaded to S3 and no Secrets
    Manager secret is created - under v3 the certificate goes back to the host
    that requested it, and the private key never existed here.

    The two CA backends differ in how much of the CSR they trust, and the
    difference is security-relevant because a compromised host controls its own
    CSR:

    * **Self-signed** - we build the certificate ourselves, so the subject is
      rebuilt from ``hostname`` and the CSR contributes only a public key.
    * **ACM Private CA** - PCA copies the subject out of the CSR and the
      EndEntityClientAuthCertificate template does not allow overriding it.
      We therefore *verify* the CSR's CN equals ``hostname`` and refuse to
      submit it otherwise, which is the closest equivalent guarantee.
    """
    # Validate before either backend: parses, self-signature verifies (proof of
    # possession), key type/size acceptable.
    match crypto.parse_and_validate_csr(csr_pem):
        case Err(e):
            return Err(e)
        case Ok(csr):
            pass

    match scope_ca.mode:
        case CAMode.SELF_SIGNED:
            # Import here to avoid a circular import via operations.ca.
            from iam_ra_cli.operations.ca import _ca_cert_s3_key, _ca_key_local_path

            ca_cert_key = _ca_cert_s3_key(namespace, scope)
            match read_object(ctx.s3, bucket_name, ca_cert_key):
                case Err(_):
                    return Err(CACertNotFoundError(bucket_name, ca_cert_key))
                case Ok(ca_cert_pem):
                    pass

            ca_key_path = _ca_key_local_path(namespace, scope)
            if not ca_key_path.exists():
                return Err(CAKeyNotFoundError(ca_key_path))

            # common_name is authoritative here - see sign_csr's docstring.
            return crypto.sign_csr(
                csr_pem=csr_pem,
                ca_cert_pem=ca_cert_pem,
                ca_key_pem=ca_key_path.read_text(),
                common_name=hostname,
                validity_days=validity_days,
            )

        case CAMode.PCA_NEW | CAMode.PCA_EXISTING:
            from botocore.exceptions import ClientError, WaiterError

            from iam_ra_cli.operations.host import PCA_CLIENT_AUTH_TEMPLATE_ARN

            # PCA takes the subject from the CSR, so a mismatched CN would
            # produce a certificate naming a host other than the one being
            # approved. Refuse rather than silently issue it.
            requested_cn = crypto.csr_common_name(csr)
            if requested_cn != hostname:
                return Err(
                    CsrSubjectMismatchError(
                        expected_common_name=hostname,
                        requested_common_name=requested_cn,
                    )
                )

            assert scope_ca.pca_arn is not None
            pca_arn = str(scope_ca.pca_arn)

            try:
                desc = ctx.acm_pca.describe_certificate_authority(
                    CertificateAuthorityArn=pca_arn
                )
            except ClientError as e:
                return Err(PCADescribeError(pca_arn, str(e)))

            ca_info = desc["CertificateAuthority"]
            status = ca_info.get("Status", "UNKNOWN")
            if status != "ACTIVE":
                return Err(PCANotActiveError(pca_arn, status))
            signing_algorithm = ca_info["CertificateAuthorityConfiguration"][
                "SigningAlgorithm"
            ]

            try:
                issue = ctx.acm_pca.issue_certificate(
                    CertificateAuthorityArn=pca_arn,
                    Csr=csr_pem.encode("utf-8"),
                    SigningAlgorithm=signing_algorithm,
                    Validity={"Value": validity_days, "Type": "DAYS"},
                    TemplateArn=PCA_CLIENT_AUTH_TEMPLATE_ARN,
                )
            except ClientError as e:
                return Err(PCAIssueCertError(pca_arn, str(e)))

            cert_arn = issue["CertificateArn"]

            waiter = ctx.acm_pca.get_waiter("certificate_issued")
            try:
                waiter.wait(
                    CertificateAuthorityArn=pca_arn,
                    CertificateArn=cert_arn,
                    WaiterConfig={"Delay": 2, "MaxAttempts": 60},
                )
            except WaiterError:
                return Err(PCATimeoutError(pca_arn, cert_arn))

            try:
                got = ctx.acm_pca.get_certificate(
                    CertificateAuthorityArn=pca_arn,
                    CertificateArn=cert_arn,
                )
            except ClientError as e:
                return Err(PCAGetCertError(pca_arn, cert_arn, str(e)))

            return Ok(got["Certificate"])
