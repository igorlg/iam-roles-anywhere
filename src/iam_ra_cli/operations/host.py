"""Host operations - teardown of legacy (v2/v3) host resources.

Certificate issuance moved to :mod:`iam_ra_cli.operations.enrol` in v3, where
the CSR comes from the host and no private key is generated, uploaded or
escrowed here.

What remains is teardown. Hosts onboarded under v2/v3 have a CloudFormation
stack holding two Secrets Manager secrets, plus a certificate and private key in
S3, and those still need removing when such a host is offboarded. v4 hosts have
none of that - see ``Host.stack_name is None`` handling in the offboard
workflow.
"""

from iam_ra_cli.lib.aws import AwsContext
from iam_ra_cli.lib.cfn import delete_stack
from iam_ra_cli.lib.errors import StackDeleteError
from iam_ra_cli.lib.result import Err, Ok, Result
from iam_ra_cli.lib.storage.s3 import delete_object

# End-entity template for client authentication - required by IAM Roles Anywhere.
# Still used by operations/enrol.py on the ACM Private CA path.
PCA_CLIENT_AUTH_TEMPLATE_ARN = (
    "arn:aws:acm-pca:::template/EndEntityClientAuthCertificate/V1"
)


def _stack_name(namespace: str, hostname: str) -> str:
    return f"iam-ra-{namespace}-host-{hostname}"


def _cert_s3_key(namespace: str, hostname: str) -> str:
    return f"{namespace}/hosts/{hostname}/certificate.pem"


def _key_s3_key(namespace: str, hostname: str) -> str:
    return f"{namespace}/hosts/{hostname}/private-key.pem"


def offboard_host(
    ctx: AwsContext,
    stack_name: str,
    bucket_name: str,
    namespace: str,
    hostname: str,
) -> Result[None, StackDeleteError]:
    """Tear down a legacy host's AWS resources.

    1. Delete the host stack (which deletes its Secrets Manager secrets)
    2. Delete the host cert/key objects from S3

    Only meaningful for hosts onboarded under v2/v3. The offboard workflow skips
    this entirely for v4 hosts, which have no stack and no S3 objects.

    Note this does not revoke anything: an already-issued certificate stays
    valid against the trust anchor until it expires, in both versions.
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
