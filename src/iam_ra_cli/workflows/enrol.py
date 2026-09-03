"""Enrolment workflows - request, approve, enrol.

The v3 replacement for `host onboard`. The private key is generated on the host
that will use it and never leaves; only a CSR and a certificate move, and both
are public.

Three verbs, deliberately distinct rather than flags on one command, because
their preconditions genuinely differ:

``request``  Runs on the host. Generates a key in a KeyStore and emits a CSR.
             **Takes no AwsContext** - it needs no AWS credentials at all, and
             the signature enforces that rather than merely documenting it.
``approve``  Runs wherever the CA lives (the admin workstation for a
             self-signed CA). Validates and signs a CSR, records the host.
``enrol``    Both halves in one process, for the common case where the machine
             that needs credentials is also the one with AWS access.
"""

from dataclasses import dataclass
from pathlib import Path

from iam_ra_cli.lib import keystore as keystore_module
from iam_ra_cli.lib import state as state_module
from iam_ra_cli.lib.aws import AwsContext
from iam_ra_cli.lib.crypto import CertificateInfo, inspect_certificate
from iam_ra_cli.lib.errors import (
    AccountMismatchError,
    CAScopeNotFoundError,
    HostAlreadyExistsError,
    KeyStoreError,
    NotInitializedError,
    RoleNotFoundError,
    StateLoadError,
    StateSaveError,
)
from iam_ra_cli.lib.keystore import CredentialSource, KeyStoreBackend, make_label
from iam_ra_cli.lib.preflight import check_account_matches_namespace
from iam_ra_cli.lib.result import Err, Ok, Result
from iam_ra_cli.models import CA, Arn, Host, State
from iam_ra_cli.operations.enrol import SignHostCsrError, sign_host_csr
from iam_ra_cli.workflows.host import RoleProfile

type RequestError = KeyStoreError

type ApproveError = (
    NotInitializedError
    | AccountMismatchError
    | RoleNotFoundError
    | CAScopeNotFoundError
    | HostAlreadyExistsError
    | SignHostCsrError
    | StateLoadError
    | StateSaveError
)

type EnrolError = ApproveError | KeyStoreError


# =============================================================================
# request - runs on the host, no AWS access
# =============================================================================


@dataclass(frozen=True)
class RequestConfig:
    """Inputs for generating a key and CSR on a host.

    `scope` cannot be derived from the role list here the way it is in
    ``approve``, because that lookup needs AWS access and ``request``
    deliberately has none. It only affects the KeyStore label, so the default
    is right for single-scope setups; multi-scope users must pass the same
    scope they will approve under.
    """

    namespace: str
    hostname: str
    scope: str = "default"
    key_store: KeyStoreBackend = "files"
    overwrite: bool = False
    # Test seam: override where the files backend puts keys.
    key_store_root: Path | None = None


@dataclass(frozen=True)
class RequestResult:
    """Public output of a request. Carries no private key - by design."""

    hostname: str
    namespace: str
    scope: str
    label: str
    key_store: str
    csr_pem: str


def request_certificate(config: RequestConfig) -> Result[RequestResult, RequestError]:
    """Generate a key in the host's key store and return a CSR for it.

    Note the absent ``ctx`` parameter: this makes no AWS calls and reads no
    credentials, so it can run on a host that has no AWS access whatsoever.
    """
    match keystore_module.get_keystore(config.key_store, root=config.key_store_root):
        case Err(e):
            return Err(e)
        case Ok(store):
            pass

    label = make_label(config.namespace, config.scope)

    match store.generate(label, config.hostname, overwrite=config.overwrite):
        case Err(e):
            return Err(e)
        case Ok(enrolment_request):
            pass

    return Ok(
        RequestResult(
            hostname=config.hostname,
            namespace=config.namespace,
            scope=config.scope,
            label=label,
            key_store=config.key_store,
            csr_pem=enrolment_request.csr_pem,
        )
    )


# =============================================================================
# approve - runs where the CA lives
# =============================================================================


@dataclass(frozen=True)
class ApproveConfig:
    """Inputs for signing a host's CSR and recording the host.

    `key_store` is advisory metadata: the admin cannot verify from a CSR where
    the host keeps its key, so this records what the host reported. It is used
    for inventory and for `iam-ra status`, never for a security decision.
    """

    namespace: str
    hostname: str
    role_names: tuple[str, ...]
    csr_pem: str
    key_store: str = "files"
    validity_days: int = 365
    overwrite: bool = False


@dataclass(frozen=True)
class ApproveResult:
    """Everything the CLI needs to hand back after approving a request."""

    host: Host
    namespace: str
    region: str
    scope: str
    certificate_pem: str
    certificate: CertificateInfo
    trust_anchor_arn: Arn
    role_profiles: tuple[RoleProfile, ...]


def _resolve_roles_and_scope(
    state: State, namespace: str, role_names: tuple[str, ...]
) -> Result[tuple[str, CA, tuple[RoleProfile, ...]], ApproveError]:
    """Validate the role list and resolve the single scope it implies.

    All of a host's roles must live in one scope, because a certificate
    authenticates against exactly one trust anchor. Mirrors the same checks in
    the legacy onboard workflow.
    """
    if not role_names:
        return Err(RoleNotFoundError(namespace, ""))

    for role_name in role_names:
        if role_name not in state.roles:
            return Err(RoleNotFoundError(namespace, role_name))

    roles = [state.roles[name] for name in role_names]
    scopes = {role.scope for role in roles}
    if len(scopes) > 1:
        return Err(
            CAScopeNotFoundError(
                namespace,
                (
                    f"roles span multiple scopes ({', '.join(sorted(scopes))}); "
                    "all roles for one host must share a scope"
                ),
            )
        )

    scope = roles[0].scope
    if scope not in state.cas:
        return Err(CAScopeNotFoundError(namespace, scope))

    role_profiles = tuple(
        RoleProfile(
            role_name=name,
            role_arn=state.roles[name].role_arn,
            profile_arn=state.roles[name].profile_arn,
        )
        for name in role_names
    )
    return Ok((scope, state.cas[scope], role_profiles))


def approve_certificate(
    ctx: AwsContext, config: ApproveConfig
) -> Result[ApproveResult, ApproveError]:
    """Validate and sign a host's CSR, then record the host in state.

    No private key is involved at any point.
    """
    match state_module.load(ctx.ssm, ctx.s3, config.namespace):
        case Err(e):
            return Err(e)
        case Ok(None):
            return Err(NotInitializedError(config.namespace))
        case Ok(state):
            pass

    if not state.is_initialized:
        return Err(NotInitializedError(config.namespace))
    assert state.init is not None

    # Fail fast if the active credentials are for the wrong AWS account.
    match check_account_matches_namespace(ctx, state):
        case Err() as e:
            return e
        case Ok(_):
            pass

    match _resolve_roles_and_scope(state, config.namespace, config.role_names):
        case Err(e):
            return Err(e)
        case Ok((scope, scope_ca, role_profiles)):
            pass

    if config.hostname in state.hosts and not config.overwrite:
        return Err(HostAlreadyExistsError(config.namespace, config.hostname))

    match sign_host_csr(
        ctx,
        namespace=config.namespace,
        hostname=config.hostname,
        scope=scope,
        scope_ca=scope_ca,
        bucket_name=state.init.bucket_arn.resource_id,
        csr_pem=config.csr_pem,
        validity_days=config.validity_days,
    ):
        case Err(e):
            return Err(e)
        case Ok(certificate_pem):
            pass

    # Record serial + expiry so `iam-ra status` can identify and age-check the
    # certificate without state having to hold the certificate itself.
    match inspect_certificate(certificate_pem):
        case Err(e):
            return Err(e)
        case Ok(cert_info):
            pass

    host = Host(
        hostname=config.hostname,
        role_names=tuple(config.role_names),
        scope=scope,
        key_store=config.key_store,
        certificate_serial=cert_info.serial,
        not_after=cert_info.not_after,
    )

    state.hosts[config.hostname] = host
    match state_module.save(ctx.ssm, ctx.s3, state):
        case Err() as e:
            return e
        case Ok(_):
            pass

    return Ok(
        ApproveResult(
            host=host,
            namespace=config.namespace,
            region=ctx.region,
            scope=scope,
            certificate_pem=certificate_pem,
            certificate=cert_info,
            trust_anchor_arn=scope_ca.trust_anchor_arn,
            role_profiles=role_profiles,
        )
    )


# =============================================================================
# enrol - both halves, one machine
# =============================================================================


@dataclass(frozen=True)
class EnrolConfig:
    """Inputs for a one-shot enrolment on the machine that needs credentials."""

    namespace: str
    hostname: str
    role_names: tuple[str, ...]
    key_store: KeyStoreBackend = "files"
    validity_days: int = 365
    overwrite: bool = False
    key_store_root: Path | None = None


@dataclass(frozen=True)
class EnrolResult:
    """Result of a one-shot enrolment, including where the credential lives."""

    approve: ApproveResult
    label: str
    key_store: str
    credential_source: CredentialSource


def enrol_host(ctx: AwsContext, config: EnrolConfig) -> Result[EnrolResult, EnrolError]:
    """Generate a key, get a certificate for it, and install it locally.

    The scope is resolved from the roles *before* the key is generated, so the
    key store label matches the scope the certificate is issued under. Doing it
    the other way round would strand a key under the wrong label whenever the
    roles imply a non-default scope.
    """
    match state_module.load(ctx.ssm, ctx.s3, config.namespace):
        case Err(e):
            return Err(e)
        case Ok(None):
            return Err(NotInitializedError(config.namespace))
        case Ok(state):
            pass

    if not state.is_initialized:
        return Err(NotInitializedError(config.namespace))

    match check_account_matches_namespace(ctx, state):
        case Err() as e:
            return e
        case Ok(_):
            pass

    match _resolve_roles_and_scope(state, config.namespace, config.role_names):
        case Err(e):
            return Err(e)
        case Ok((scope, _scope_ca, _role_profiles)):
            pass

    if config.hostname in state.hosts and not config.overwrite:
        return Err(HostAlreadyExistsError(config.namespace, config.hostname))

    match keystore_module.get_keystore(config.key_store, root=config.key_store_root):
        case Err(e):
            return Err(e)
        case Ok(store):
            pass

    match request_certificate(
        RequestConfig(
            namespace=config.namespace,
            hostname=config.hostname,
            scope=scope,
            key_store=config.key_store,
            overwrite=config.overwrite,
            key_store_root=config.key_store_root,
        )
    ):
        case Err(e):
            return Err(e)
        case Ok(request_result):
            pass

    # approve_certificate reloads state. That is a deliberate extra read rather
    # than threading the already-loaded document through: it keeps approve
    # usable standalone and keeps the two paths on one code path.
    match approve_certificate(
        ctx,
        ApproveConfig(
            namespace=config.namespace,
            hostname=config.hostname,
            role_names=config.role_names,
            csr_pem=request_result.csr_pem,
            key_store=config.key_store,
            validity_days=config.validity_days,
            overwrite=config.overwrite,
        ),
    ):
        case Err(e):
            return Err(e)
        case Ok(approve_result):
            pass

    match store.install_certificate(request_result.label, approve_result.certificate_pem):
        case Err(e):
            return Err(e)
        case Ok(credential_source):
            pass

    return Ok(
        EnrolResult(
            approve=approve_result,
            label=request_result.label,
            key_store=config.key_store,
            credential_source=credential_source,
        )
    )
