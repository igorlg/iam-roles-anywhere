"""Tests for workflows/enrol.py - request / install / approve / enrol.

The properties worth protecting here are security properties, not just
plumbing:

  * `request` must work with no AWS access at all.
  * No private key may appear in any returned value.
  * A signed certificate must name the host being approved, not the host the
    CSR asked to be.
"""

import dataclasses
import inspect
import tempfile
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from moto import mock_aws

from iam_ra_cli.lib import crypto
from iam_ra_cli.lib.aws import AwsContext
from iam_ra_cli.lib.errors import (
    CAKeyNotFoundError,
    CsrInvalidSignatureError,
    CsrSubjectMismatchError,
    CsrUnsupportedKeyError,
    HostAlreadyExistsError,
    KeyAlreadyExistsError,
    NotInitializedError,
    RoleNotFoundError,
)
from iam_ra_cli.lib.keystore import FileCredentialSource, FileKeyStore
from iam_ra_cli.lib.result import Err, Ok
from iam_ra_cli.models import CA, Arn, CAMode, Host, Init, NamespaceInfo, Role, State
from iam_ra_cli.workflows.enrol import (
    ApproveConfig,
    EnrolConfig,
    InstallConfig,
    RequestConfig,
    approve_certificate,
    enrol_host,
    install_certificate,
    request_certificate,
)

ACCOUNT = "123456789012"
BUCKET = "test-bucket"


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def aws_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "ap-southeast-2")


@pytest.fixture
def xdg(monkeypatch: pytest.MonkeyPatch):
    """Isolate XDG dirs and the state cache.

    XDG_DATA_HOME matters because the self-signed CA private key is read from
    there; the state cache must be isolated so tests do not read each other's.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        (base / "data").mkdir()
        (base / "state").mkdir()
        monkeypatch.setenv("XDG_DATA_HOME", str(base / "data"))
        monkeypatch.setenv("XDG_STATE_HOME", str(base / "state"))

        def cache_path(namespace: str) -> Path:
            return base / "cache" / namespace / "state.json"

        monkeypatch.setattr("iam_ra_cli.lib.state.paths.state_cache_path", cache_path)
        yield base


def _state(*, mode: CAMode = CAMode.SELF_SIGNED, extra_scope: bool = False) -> State:
    cas = {
        "default": CA(
            stack_name="iam-ra-test-ca-default",
            mode=mode,
            trust_anchor_arn=Arn(
                f"arn:aws:rolesanywhere:ap-southeast-2:{ACCOUNT}:trust-anchor/ta-default"
            ),
            pca_arn=(
                Arn(f"arn:aws:acm-pca:ap-southeast-2:{ACCOUNT}:certificate-authority/pca-1")
                if mode is not CAMode.SELF_SIGNED
                else None
            ),
        )
    }
    roles = {
        "admin": Role(
            stack_name="iam-ra-test-role-admin",
            role_arn=Arn(f"arn:aws:iam::{ACCOUNT}:role/admin"),
            profile_arn=Arn(
                f"arn:aws:rolesanywhere:ap-southeast-2:{ACCOUNT}:profile/admin-profile"
            ),
            scope="default",
        ),
        "readonly": Role(
            stack_name="iam-ra-test-role-readonly",
            role_arn=Arn(f"arn:aws:iam::{ACCOUNT}:role/readonly"),
            profile_arn=Arn(f"arn:aws:rolesanywhere:ap-southeast-2:{ACCOUNT}:profile/ro-profile"),
            scope="default",
        ),
    }
    if extra_scope:
        cas["other"] = CA(
            stack_name="iam-ra-test-ca-other",
            mode=CAMode.SELF_SIGNED,
            trust_anchor_arn=Arn(
                f"arn:aws:rolesanywhere:ap-southeast-2:{ACCOUNT}:trust-anchor/ta-other"
            ),
        )
        roles["otherrole"] = Role(
            stack_name="iam-ra-test-role-other",
            role_arn=Arn(f"arn:aws:iam::{ACCOUNT}:role/other"),
            profile_arn=Arn(
                f"arn:aws:rolesanywhere:ap-southeast-2:{ACCOUNT}:profile/other-profile"
            ),
            scope="other",
        )

    return State(
        namespace="test",
        region="ap-southeast-2",
        version="3.0.0-dev",
        namespace_info=NamespaceInfo(account_id=ACCOUNT, region="ap-southeast-2"),
        init=Init(
            stack_name="iam-ra-test-init",
            bucket_arn=Arn(f"arn:aws:s3:::{BUCKET}"),
            kms_key_arn=Arn(f"arn:aws:kms:ap-southeast-2:{ACCOUNT}:key/test-key"),
        ),
        cas=cas,
        roles=roles,
    )


@pytest.fixture
def env(aws_credentials, xdg):
    """A mocked AWS account with state, a CA cert in S3 and a CA key on disk."""
    from iam_ra_cli.lib import paths

    with mock_aws():
        ctx = AwsContext(region="ap-southeast-2", profile=None)
        ctx.s3.create_bucket(
            Bucket=BUCKET,
            CreateBucketConfiguration={"LocationConstraint": "ap-southeast-2"},
        )

        ca = crypto.generate_ca(common_name="IAM Roles Anywhere CA (test/default)")
        # Where operations/ca.py expects to find CA material.
        ctx.s3.put_object(
            Bucket=BUCKET,
            Key="test/scopes/default/ca/certificate.pem",
            Body=ca.certificate.encode(),
        )
        key_path = paths.data_dir() / "test" / "scopes" / "default" / "ca-private-key.pem"
        key_path.parent.mkdir(parents=True, exist_ok=True)
        key_path.write_text(ca.private_key)

        def put_state(state: State) -> None:
            ctx.s3.put_object(
                Bucket=BUCKET,
                Key="test/state.json",
                Body=state.to_json().encode(),
            )
            ctx.ssm.put_parameter(
                Name="/iam-ra/test/state-location",
                Value=f"s3://{BUCKET}/test/state.json",
                Type="String",
                Overwrite=True,
            )

        put_state(_state())
        yield ctx, put_state, ca, xdg


def _unwrap(result):  # noqa: ANN001, ANN202
    match result:
        case Ok(v):
            return v
        case Err(e):
            pytest.fail(f"expected Ok, got Err({e})")


def _store(xdg_base: Path) -> FileKeyStore:
    return FileKeyStore(root=xdg_base / "state" / "iam-ra" / "keys")


# =============================================================================
# request
# =============================================================================


class TestRequestCertificate:
    def test_takes_no_aws_context(self) -> None:
        """The signature itself must guarantee `request` needs no credentials.

        This is the headline property of the split flow: a host with no AWS
        access can still enrol. Asserting on the signature stops a future
        refactor from quietly adding an AWS dependency.
        """
        params = inspect.signature(request_certificate).parameters

        assert list(params) == ["config"]
        assert "ctx" not in params

    def test_generates_key_and_returns_csr(self, xdg: Path) -> None:
        result = _unwrap(request_certificate(RequestConfig(namespace="test", hostname="web01")))

        assert result.csr_pem.startswith("-----BEGIN CERTIFICATE REQUEST-----")
        assert result.label == "test-default"
        assert result.key_store == "files"
        assert _store(xdg).has_key("test-default")

    def test_result_carries_no_private_key(self, xdg: Path) -> None:
        result = _unwrap(request_certificate(RequestConfig(namespace="test", hostname="web01")))

        for f in dataclasses.fields(result):
            assert "PRIVATE KEY" not in str(getattr(result, f.name))

    def test_csr_matches_the_stored_key(self, xdg: Path) -> None:
        result = _unwrap(request_certificate(RequestConfig(namespace="test", hostname="web01")))

        csr = x509.load_pem_x509_csr(result.csr_pem.encode())
        stored = serialization.load_pem_private_key(
            _store(xdg).key_path("test-default").read_bytes(), password=None
        )
        spki = serialization.PublicFormat.SubjectPublicKeyInfo
        assert csr.public_key().public_bytes(
            serialization.Encoding.DER, spki
        ) == stored.public_key().public_bytes(serialization.Encoding.DER, spki)

    def test_scope_is_reflected_in_the_label(self, xdg: Path) -> None:
        result = _unwrap(
            request_certificate(RequestConfig(namespace="test", hostname="web01", scope="other"))
        )

        assert result.label == "test-other"

    def test_refuses_to_clobber_an_existing_key(self, xdg: Path) -> None:
        _unwrap(request_certificate(RequestConfig(namespace="test", hostname="web01")))

        match request_certificate(RequestConfig(namespace="test", hostname="web01")):
            case Err(e):
                assert isinstance(e, KeyAlreadyExistsError)
            case Ok(_):
                pytest.fail("second request should be refused without --overwrite")

    def test_overwrite_regenerates(self, xdg: Path) -> None:
        first = _unwrap(request_certificate(RequestConfig(namespace="test", hostname="web01")))
        second = _unwrap(
            request_certificate(RequestConfig(namespace="test", hostname="web01", overwrite=True))
        )

        assert first.csr_pem != second.csr_pem

    def test_unknown_backend_fails(self, xdg: Path) -> None:
        """Deliberately does not exercise macosKeychain through this layer.

        RequestConfig has no seam for injecting a keychain path, so requesting
        that backend here would create a keychain in the real ~/Library and
        write a password into the developer's login keychain. The keychain
        backend is covered directly in tests/test_keystore.py, against a
        throwaway keychain.
        """
        match request_certificate(
            RequestConfig(
                namespace="test",
                hostname="web01",
                key_store="nonsense",  # type: ignore[arg-type]
            )
        ):
            case Err(_):
                pass
            case Ok(_):
                pytest.fail("an unknown backend should fail")


# =============================================================================
# install
# =============================================================================


class TestInstallCertificate:
    """`install` is the second half of the split flow, and also host-side.

    Without it, `request` and `approve` cannot actually produce a working host:
    the signed certificate has nowhere to go. These tests pin the properties
    that make it safe to run on a machine with no AWS access.
    """

    def _sign(self, csr_pem: str, hostname: str = "web01") -> str:
        ca = crypto.generate_ca("Test CA")
        return _unwrap(crypto.sign_csr(csr_pem, ca.certificate, ca.private_key, hostname, 30))

    def test_takes_no_aws_context(self) -> None:
        """Same guarantee as `request`: enforced by the signature, not a comment."""
        params = inspect.signature(install_certificate).parameters

        assert list(params) == ["config"]
        assert "ctx" not in params

    def test_installs_the_certificate_against_the_waiting_key(self, xdg: Path) -> None:
        req = _unwrap(request_certificate(RequestConfig(namespace="test", hostname="web01")))
        store = _store(xdg)
        assert not store.certificate_path("test-default").exists()

        result = _unwrap(
            install_certificate(
                InstallConfig(namespace="test", certificate_pem=self._sign(req.csr_pem))
            )
        )

        assert store.certificate_path("test-default").exists()
        assert result.label == "test-default"
        assert result.certificate.subject_common_name == "web01"
        assert isinstance(result.credential_source, FileCredentialSource)

    def test_installed_certificate_matches_the_stored_key(self, xdg: Path) -> None:
        """The whole point: the pair on disk must actually be a usable identity."""
        req = _unwrap(request_certificate(RequestConfig(namespace="test", hostname="web01")))
        _unwrap(
            install_certificate(
                InstallConfig(namespace="test", certificate_pem=self._sign(req.csr_pem))
            )
        )

        store = _store(xdg)
        cert = x509.load_pem_x509_certificate(store.certificate_path("test-default").read_bytes())
        key = serialization.load_pem_private_key(
            store.key_path("test-default").read_bytes(), password=None
        )
        spki = serialization.PublicFormat.SubjectPublicKeyInfo
        assert cert.public_key().public_bytes(
            serialization.Encoding.DER, spki
        ) == key.public_key().public_bytes(serialization.Encoding.DER, spki)

    def test_reports_serial_and_expiry(self, xdg: Path) -> None:
        req = _unwrap(request_certificate(RequestConfig(namespace="test", hostname="web01")))

        result = _unwrap(
            install_certificate(
                InstallConfig(namespace="test", certificate_pem=self._sign(req.csr_pem))
            )
        )

        assert result.certificate.serial == result.certificate.serial.upper()
        assert not result.certificate.serial.startswith("0")
        assert result.certificate.not_after > result.certificate.not_before

    def test_refuses_a_certificate_for_a_different_key(self, xdg: Path) -> None:
        """A certificate issued to another host must not install here.

        Otherwise an attacker who can drop a file on the host, or an admin who
        mixes up two PEMs during a bulk migration, silently produces a
        cert/key pair that cannot authenticate - failing at credential time
        with no clue why.
        """
        _unwrap(request_certificate(RequestConfig(namespace="test", hostname="web01")))
        foreign_csr = crypto.build_csr(crypto.generate_private_key(), "web01")

        match install_certificate(
            InstallConfig(namespace="test", certificate_pem=self._sign(foreign_csr))
        ):
            case Err(e):
                assert "does not match" in e.reason
            case Ok(_):
                pytest.fail("a certificate for a different key must be refused")

    def test_refuses_a_certificate_superseded_by_a_new_request(self, xdg: Path) -> None:
        """Re-requesting rotates the key, which must invalidate the older cert."""
        first = _unwrap(request_certificate(RequestConfig(namespace="test", hostname="web01")))
        stale = self._sign(first.csr_pem)
        _unwrap(
            request_certificate(RequestConfig(namespace="test", hostname="web01", overwrite=True))
        )

        match install_certificate(InstallConfig(namespace="test", certificate_pem=stale)):
            case Err(e):
                assert "does not match" in e.reason
            case Ok(_):
                pytest.fail("a certificate for the superseded key must be refused")

    def test_fails_when_no_key_was_requested(self, xdg: Path) -> None:
        other = _unwrap(request_certificate(RequestConfig(namespace="other", hostname="web01")))

        match install_certificate(
            InstallConfig(namespace="test", certificate_pem=self._sign(other.csr_pem))
        ):
            case Err(_):
                pass
            case Ok(_):
                pytest.fail("installing without a prior request must fail")

    def test_rejects_a_malformed_certificate(self, xdg: Path) -> None:
        _unwrap(request_certificate(RequestConfig(namespace="test", hostname="web01")))

        match install_certificate(
            InstallConfig(namespace="test", certificate_pem="not a certificate")
        ):
            case Err(_):
                pass
            case Ok(_):
                pytest.fail("a malformed certificate must be refused")

    def test_scope_selects_which_key_to_pair_with(self, xdg: Path) -> None:
        _unwrap(request_certificate(RequestConfig(namespace="test", hostname="web01")))
        other = _unwrap(
            request_certificate(RequestConfig(namespace="test", hostname="web01", scope="other"))
        )

        result = _unwrap(
            install_certificate(
                InstallConfig(
                    namespace="test",
                    certificate_pem=self._sign(other.csr_pem),
                    scope="other",
                )
            )
        )

        assert result.label == "test-other"
        assert not _store(xdg).certificate_path("test-default").exists()

    def test_result_carries_no_private_key(self, xdg: Path) -> None:
        req = _unwrap(request_certificate(RequestConfig(namespace="test", hostname="web01")))

        result = _unwrap(
            install_certificate(
                InstallConfig(namespace="test", certificate_pem=self._sign(req.csr_pem))
            )
        )

        for f in dataclasses.fields(result):
            assert "PRIVATE KEY" not in str(getattr(result, f.name))


# =============================================================================
# approve
# =============================================================================


class TestApproveCertificate:
    def _csr(self, hostname: str = "web01") -> str:
        return crypto.build_csr(crypto.generate_private_key(), hostname)

    def test_signs_and_registers_the_host(self, env) -> None:
        ctx, _put, ca, _base = env

        result = _unwrap(
            approve_certificate(
                ctx,
                ApproveConfig(
                    namespace="test",
                    hostname="web01",
                    role_names=("admin",),
                    csr_pem=self._csr(),
                ),
            )
        )

        assert result.certificate_pem.startswith("-----BEGIN CERTIFICATE-----")
        assert result.scope == "default"
        assert result.host.hostname == "web01"
        assert result.host.role_names == ("admin",)

    def test_certificate_is_signed_by_the_scope_ca(self, env) -> None:
        ctx, _put, ca, _base = env

        result = _unwrap(
            approve_certificate(
                ctx,
                ApproveConfig(
                    namespace="test",
                    hostname="web01",
                    role_names=("admin",),
                    csr_pem=self._csr(),
                ),
            )
        )

        cert = x509.load_pem_x509_certificate(result.certificate_pem.encode())
        ca_cert = x509.load_pem_x509_certificate(ca.certificate.encode())
        assert cert.issuer == ca_cert.subject
        ca_cert.public_key().verify(
            cert.signature, cert.tbs_certificate_bytes, cert.signature_algorithm_parameters
        )

    def test_records_v4_host_fields(self, env) -> None:
        ctx, _put, _ca, _base = env

        result = _unwrap(
            approve_certificate(
                ctx,
                ApproveConfig(
                    namespace="test",
                    hostname="web01",
                    role_names=("admin",),
                    csr_pem=self._csr(),
                ),
            )
        )

        host = result.host
        assert host.key_store == "files"
        assert host.certificate_serial == result.certificate.serial
        assert host.not_after == result.certificate.not_after
        # No AWS-side key escrow for a v4 host.
        assert host.stack_name is None
        assert host.private_key_secret_arn is None
        assert host.uses_host_generated_key is True
        assert host.is_legacy_managed_key is False

    def test_host_is_persisted_to_state(self, env) -> None:
        ctx, _put, _ca, _base = env
        _unwrap(
            approve_certificate(
                ctx,
                ApproveConfig(
                    namespace="test",
                    hostname="web01",
                    role_names=("admin", "readonly"),
                    csr_pem=self._csr(),
                ),
            )
        )

        from iam_ra_cli.lib import state as state_module

        reloaded = _unwrap(state_module.load(ctx.ssm, ctx.s3, "test"))
        assert reloaded.hosts["web01"].role_names == ("admin", "readonly")

    def test_result_carries_no_private_key(self, env) -> None:
        ctx, _put, _ca, _base = env
        result = _unwrap(
            approve_certificate(
                ctx,
                ApproveConfig(
                    namespace="test",
                    hostname="web01",
                    role_names=("admin",),
                    csr_pem=self._csr(),
                ),
            )
        )

        assert "PRIVATE KEY" not in result.certificate_pem

    def test_subject_comes_from_hostname_not_the_csr(self, env) -> None:
        """A self-signed CA rebuilds the subject, so a host cannot name itself
        something else even if its CSR asks to."""
        ctx, _put, _ca, _base = env

        result = _unwrap(
            approve_certificate(
                ctx,
                ApproveConfig(
                    namespace="test",
                    hostname="web01",
                    role_names=("admin",),
                    csr_pem=self._csr("admin-box"),
                ),
            )
        )

        cert = x509.load_pem_x509_certificate(result.certificate_pem.encode())
        cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0]
        assert cn.value == "web01"

    def test_rejects_unknown_role(self, env) -> None:
        ctx, _put, _ca, _base = env

        match approve_certificate(
            ctx,
            ApproveConfig(
                namespace="test",
                hostname="web01",
                role_names=("nope",),
                csr_pem=self._csr(),
            ),
        ):
            case Err(e):
                assert isinstance(e, RoleNotFoundError)
            case Ok(_):
                pytest.fail("unknown role should be refused")

    def test_rejects_roles_spanning_scopes(self, env) -> None:
        """One certificate authenticates against exactly one trust anchor."""
        ctx, put_state, _ca, _base = env
        put_state(_state(extra_scope=True))

        match approve_certificate(
            ctx,
            ApproveConfig(
                namespace="test",
                hostname="web01",
                role_names=("admin", "otherrole"),
                csr_pem=self._csr(),
            ),
        ):
            case Err(e):
                assert "multiple scopes" in str(e)
            case Ok(_):
                pytest.fail("cross-scope roles should be refused")

    def test_rejects_existing_host_without_overwrite(self, env) -> None:
        ctx, put_state, _ca, _base = env
        state = _state()
        state.hosts["web01"] = Host(hostname="web01", role_names=("admin",))
        put_state(state)

        match approve_certificate(
            ctx,
            ApproveConfig(
                namespace="test",
                hostname="web01",
                role_names=("admin",),
                csr_pem=self._csr(),
            ),
        ):
            case Err(e):
                assert isinstance(e, HostAlreadyExistsError)
            case Ok(_):
                pytest.fail("existing host should require --overwrite")

    def test_overwrite_allows_re_approval(self, env) -> None:
        ctx, put_state, _ca, _base = env
        state = _state()
        state.hosts["web01"] = Host(hostname="web01", role_names=("admin",))
        put_state(state)

        _unwrap(
            approve_certificate(
                ctx,
                ApproveConfig(
                    namespace="test",
                    hostname="web01",
                    role_names=("admin",),
                    csr_pem=self._csr(),
                    overwrite=True,
                ),
            )
        )

    def test_rejects_tampered_csr(self, env) -> None:
        """Proof of possession: a CSR whose signature does not verify must not
        be signed."""
        ctx, _put, _ca, _base = env
        import base64

        csr = x509.load_pem_x509_csr(self._csr().encode())
        der = bytearray(csr.public_bytes(serialization.Encoding.DER))
        der[-1] ^= 0xFF
        tampered = (
            "-----BEGIN CERTIFICATE REQUEST-----\n"
            + base64.encodebytes(bytes(der)).decode()
            + "-----END CERTIFICATE REQUEST-----\n"
        )

        match approve_certificate(
            ctx,
            ApproveConfig(
                namespace="test",
                hostname="web01",
                role_names=("admin",),
                csr_pem=tampered,
            ),
        ):
            case Err(e):
                assert isinstance(e, CsrInvalidSignatureError)
            case Ok(_):
                pytest.fail("tampered CSR should be refused")

    def test_rejects_unusable_key_type(self, env) -> None:
        ctx, _put, _ca, _base = env
        from cryptography.hazmat.primitives.asymmetric import ed25519

        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "web01")]))
            .sign(ed25519.Ed25519PrivateKey.generate(), None)
        )

        match approve_certificate(
            ctx,
            ApproveConfig(
                namespace="test",
                hostname="web01",
                role_names=("admin",),
                csr_pem=csr.public_bytes(serialization.Encoding.PEM).decode(),
            ),
        ):
            case Err(e):
                assert isinstance(e, CsrUnsupportedKeyError)
            case Ok(_):
                pytest.fail("Ed25519 should be refused")

    def test_fails_when_ca_key_is_absent(self, env) -> None:
        """The admin machine must actually hold the self-signed CA key."""
        ctx, _put, _ca, base = env
        from iam_ra_cli.lib import paths

        (paths.data_dir() / "test" / "scopes" / "default" / "ca-private-key.pem").unlink()

        match approve_certificate(
            ctx,
            ApproveConfig(
                namespace="test",
                hostname="web01",
                role_names=("admin",),
                csr_pem=self._csr(),
            ),
        ):
            case Err(e):
                assert isinstance(e, CAKeyNotFoundError)
            case Ok(_):
                pytest.fail("missing CA key should fail")

    def test_fails_when_not_initialized(self, aws_credentials, xdg) -> None:
        with mock_aws():
            ctx = AwsContext(region="ap-southeast-2", profile=None)
            match approve_certificate(
                ctx,
                ApproveConfig(
                    namespace="test",
                    hostname="web01",
                    role_names=("admin",),
                    csr_pem=self._csr(),
                ),
            ):
                case Err(e):
                    assert isinstance(e, NotInitializedError)
                case Ok(_):
                    pytest.fail("uninitialized namespace should fail")


class TestApprovePcaSubjectCheck:
    """ACM Private CA copies the subject out of the CSR and the client-auth
    template does not allow overriding it, so a mismatched CN must be a refusal
    rather than a silently-wrong certificate."""

    def test_rejects_csr_naming_a_different_host(self, env) -> None:
        ctx, put_state, _ca, _base = env
        put_state(_state(mode=CAMode.PCA_EXISTING))

        csr = crypto.build_csr(crypto.generate_private_key(), "admin-box")

        match approve_certificate(
            ctx,
            ApproveConfig(
                namespace="test",
                hostname="web01",
                role_names=("admin",),
                csr_pem=csr,
            ),
        ):
            case Err(e):
                assert isinstance(e, CsrSubjectMismatchError)
                assert e.expected_common_name == "web01"
                assert e.requested_common_name == "admin-box"
            case Ok(_):
                pytest.fail("PCA path must refuse a mismatched CN")


# =============================================================================
# enrol
# =============================================================================


class TestEnrolHost:
    def test_end_to_end(self, env) -> None:
        ctx, _put, ca, base = env

        result = _unwrap(
            enrol_host(
                ctx,
                EnrolConfig(namespace="test", hostname="mbp", role_names=("admin",)),
            )
        )

        assert result.label == "test-default"
        assert result.key_store == "files"
        assert isinstance(result.credential_source, FileCredentialSource)
        assert result.approve.host.key_store == "files"

    def test_installs_a_certificate_matching_the_key(self, env) -> None:
        ctx, _put, _ca, base = env

        result = _unwrap(
            enrol_host(
                ctx,
                EnrolConfig(namespace="test", hostname="mbp", role_names=("admin",)),
            )
        )

        source = result.credential_source
        assert isinstance(source, FileCredentialSource)
        cert = x509.load_pem_x509_certificate(source.certificate_path.read_bytes())
        key = serialization.load_pem_private_key(
            source.private_key_path.read_bytes(), password=None
        )
        spki = serialization.PublicFormat.SubjectPublicKeyInfo
        assert cert.public_key().public_bytes(
            serialization.Encoding.DER, spki
        ) == key.public_key().public_bytes(serialization.Encoding.DER, spki)

    def test_certificate_cn_is_the_hostname(self, env) -> None:
        ctx, _put, _ca, _base = env

        result = _unwrap(
            enrol_host(
                ctx,
                EnrolConfig(namespace="test", hostname="mbp", role_names=("admin",)),
            )
        )

        assert result.approve.certificate.subject_common_name == "mbp"

    def test_key_is_owner_only(self, env) -> None:
        ctx, _put, _ca, _base = env
        import stat

        result = _unwrap(
            enrol_host(
                ctx,
                EnrolConfig(namespace="test", hostname="mbp", role_names=("admin",)),
            )
        )

        source = result.credential_source
        assert isinstance(source, FileCredentialSource)
        assert stat.S_IMODE(source.private_key_path.stat().st_mode) == 0o600

    def test_label_uses_the_scope_implied_by_the_roles(self, env) -> None:
        """The key must be stored under the scope the certificate is issued
        under, not under the default."""
        ctx, put_state, _ca, base = env
        put_state(_state(extra_scope=True))

        # Give the "other" scope its own CA material.
        from iam_ra_cli.lib import paths

        other_ca = crypto.generate_ca(common_name="IAM Roles Anywhere CA (test/other)")
        ctx.s3.put_object(
            Bucket=BUCKET,
            Key="test/scopes/other/ca/certificate.pem",
            Body=other_ca.certificate.encode(),
        )
        other_key = paths.data_dir() / "test" / "scopes" / "other" / "ca-private-key.pem"
        other_key.parent.mkdir(parents=True, exist_ok=True)
        other_key.write_text(other_ca.private_key)

        result = _unwrap(
            enrol_host(
                ctx,
                EnrolConfig(namespace="test", hostname="mbp", role_names=("otherrole",)),
            )
        )

        assert result.approve.scope == "other"
        assert result.label == "test-other"

    def test_validates_roles_before_generating_a_key(self, env) -> None:
        """A bad role list must not leave a stray key behind."""
        ctx, _put, _ca, base = env

        match enrol_host(
            ctx,
            EnrolConfig(namespace="test", hostname="mbp", role_names=("nope",)),
        ):
            case Err(e):
                assert isinstance(e, RoleNotFoundError)
            case Ok(_):
                pytest.fail("unknown role should be refused")

        assert not _store(base).has_key("test-default")

    def test_refuses_existing_host_before_generating_a_key(self, env) -> None:
        ctx, put_state, _ca, base = env
        state = _state()
        state.hosts["mbp"] = Host(hostname="mbp", role_names=("admin",))
        put_state(state)

        match enrol_host(ctx, EnrolConfig(namespace="test", hostname="mbp", role_names=("admin",))):
            case Err(e):
                assert isinstance(e, HostAlreadyExistsError)
            case Ok(_):
                pytest.fail("existing host should require --overwrite")

        assert not _store(base).has_key("test-default")

    def test_overwrite_re_enrols_with_a_fresh_key(self, env) -> None:
        ctx, _put, _ca, base = env

        first = _unwrap(
            enrol_host(ctx, EnrolConfig(namespace="test", hostname="mbp", role_names=("admin",)))
        )
        first_key = _store(base).key_path("test-default").read_text()

        second = _unwrap(
            enrol_host(
                ctx,
                EnrolConfig(
                    namespace="test",
                    hostname="mbp",
                    role_names=("admin",),
                    overwrite=True,
                ),
            )
        )

        assert _store(base).key_path("test-default").read_text() != first_key
        assert second.approve.certificate.serial != first.approve.certificate.serial
