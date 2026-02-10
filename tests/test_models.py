"""Tests for models - Arn, State, and related data structures."""

import json

import pytest

from iam_ra_cli.models import CA, Arn, CAMode, Host, Init, Role, State


class TestArn:
    """Tests for Arn class."""

    def test_valid_arn_parsing(self) -> None:
        arn = Arn("arn:aws:s3:::my-bucket")
        assert arn.arn_partition == "aws"
        assert arn.service == "s3"
        assert arn.region == ""
        assert arn.account == ""
        assert arn.resource == "my-bucket"

    def test_arn_with_all_parts(self) -> None:
        arn = Arn("arn:aws:iam::123456789012:role/my-role")
        assert arn.arn_partition == "aws"
        assert arn.service == "iam"
        assert arn.region == ""
        assert arn.account == "123456789012"
        assert arn.resource == "role/my-role"
        assert arn.resource_type == "role"
        assert arn.resource_id == "my-role"

    def test_arn_with_region(self) -> None:
        arn = Arn("arn:aws:ssm:ap-southeast-2:123456789012:parameter/my-param")
        assert arn.region == "ap-southeast-2"
        assert arn.account == "123456789012"
        assert arn.resource_type == "parameter"
        assert arn.resource_id == "my-param"

    def test_arn_with_colon_separator(self) -> None:
        arn = Arn("arn:aws:secretsmanager:us-east-1:123456789012:secret:my-secret-AbCdEf")
        assert arn.resource_type == "secret"
        assert arn.resource_id == "my-secret-AbCdEf"

    def test_invalid_arn_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid ARN"):
            Arn("not-an-arn")

    def test_arn_missing_parts_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid ARN"):
            Arn("arn:aws:s3")

    def test_arn_is_string(self) -> None:
        arn = Arn("arn:aws:s3:::my-bucket")
        assert isinstance(arn, str)
        assert str(arn) == "arn:aws:s3:::my-bucket"
        assert f"Bucket: {arn}" == "Bucket: arn:aws:s3:::my-bucket"


class TestCAMode:
    """Tests for CAMode enum."""

    def test_self_signed_value(self) -> None:
        assert CAMode.SELF_SIGNED.value == "self-signed"

    def test_pca_new_value(self) -> None:
        assert CAMode.PCA_NEW.value == "pca-new"

    def test_pca_existing_value(self) -> None:
        assert CAMode.PCA_EXISTING.value == "pca-existing"

    def test_from_string(self) -> None:
        assert CAMode("self-signed") == CAMode.SELF_SIGNED
        assert CAMode("pca-new") == CAMode.PCA_NEW
        assert CAMode("pca-existing") == CAMode.PCA_EXISTING


class TestInit:
    """Tests for Init dataclass."""

    def test_init_creation(self) -> None:
        init = Init(
            stack_name="iam-ra-test-init",
            bucket_arn=Arn("arn:aws:s3:::test-bucket"),
            kms_key_arn=Arn("arn:aws:kms:ap-southeast-2:123456789012:key/test-key"),
        )
        assert init.stack_name == "iam-ra-test-init"
        assert init.bucket_arn.resource_id == "test-bucket"

    def test_init_is_frozen(self) -> None:
        init = Init(
            stack_name="test",
            bucket_arn=Arn("arn:aws:s3:::bucket"),
            kms_key_arn=Arn("arn:aws:kms:ap-southeast-2:123456789012:key/key"),
        )
        with pytest.raises(AttributeError):
            init.stack_name = "changed"


class TestCA:
    """Tests for CA dataclass."""

    def test_ca_self_signed(self) -> None:
        ca = CA(
            stack_name="iam-ra-test-rootca",
            mode=CAMode.SELF_SIGNED,
            trust_anchor_arn=Arn(
                "arn:aws:rolesanywhere:ap-southeast-2:123456789012:trust-anchor/ta-123"
            ),
        )
        assert ca.mode == CAMode.SELF_SIGNED
        assert ca.pca_arn is None

    def test_ca_with_pca(self) -> None:
        ca = CA(
            stack_name="iam-ra-test-rootca",
            mode=CAMode.PCA_NEW,
            trust_anchor_arn=Arn(
                "arn:aws:rolesanywhere:ap-southeast-2:123456789012:trust-anchor/ta-123"
            ),
            pca_arn=Arn("arn:aws:acm-pca:ap-southeast-2:123456789012:certificate-authority/ca-123"),
        )
        assert ca.mode == CAMode.PCA_NEW
        assert ca.pca_arn is not None


class TestRole:
    """Tests for Role dataclass."""

    def test_role_with_policies(self) -> None:
        role = Role(
            stack_name="iam-ra-test-role-admin",
            role_arn=Arn("arn:aws:iam::123456789012:role/iam-ra-test-admin"),
            profile_arn=Arn(
                "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/profile-123"
            ),
            policies=(
                Arn("arn:aws:iam::aws:policy/AdministratorAccess"),
                Arn("arn:aws:iam::aws:policy/ReadOnlyAccess"),
            ),
        )
        assert len(role.policies) == 2
        assert all(isinstance(p, Arn) for p in role.policies)

    def test_role_without_policies(self) -> None:
        role = Role(
            stack_name="test",
            role_arn=Arn("arn:aws:iam::123456789012:role/test"),
            profile_arn=Arn("arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/test"),
        )
        assert role.policies == ()


class TestHost:
    """Tests for Host dataclass."""

    def test_host_creation(self) -> None:
        host = Host(
            stack_name="iam-ra-test-host-web1",
            hostname="web1",
            role_name="admin",
            certificate_secret_arn=Arn(
                "arn:aws:secretsmanager:ap-southeast-2:123456789012:secret:cert-AbCdEf"
            ),
            private_key_secret_arn=Arn(
                "arn:aws:secretsmanager:ap-southeast-2:123456789012:secret:key-AbCdEf"
            ),
        )
        assert host.hostname == "web1"
        assert host.role_name == "admin"


class TestState:
    """Tests for State dataclass."""

    def test_state_uninitialized(self) -> None:
        state = State(namespace="test", region="ap-southeast-2", version="0.1.0")
        assert state.is_initialized is False
        assert state.init is None
        assert state.ca is None
        assert state.roles == {}
        assert state.hosts == {}

    def test_state_initialized_requires_both_init_and_ca(self) -> None:
        # Only init
        state = State(
            namespace="test",
            region="ap-southeast-2",
            version="0.1.0",
            init=Init(
                stack_name="init",
                bucket_arn=Arn("arn:aws:s3:::bucket"),
                kms_key_arn=Arn("arn:aws:kms:ap-southeast-2:123456789012:key/key"),
            ),
        )
        assert state.is_initialized is False

        # Only CA
        state2 = State(
            namespace="test",
            region="ap-southeast-2",
            version="0.1.0",
            ca=CA(
                stack_name="ca",
                mode=CAMode.SELF_SIGNED,
                trust_anchor_arn=Arn(
                    "arn:aws:rolesanywhere:ap-southeast-2:123456789012:trust-anchor/ta"
                ),
            ),
        )
        assert state2.is_initialized is False

    def test_state_fully_initialized(self) -> None:
        state = State(
            namespace="test",
            region="ap-southeast-2",
            version="0.1.0",
            init=Init(
                stack_name="init",
                bucket_arn=Arn("arn:aws:s3:::bucket"),
                kms_key_arn=Arn("arn:aws:kms:ap-southeast-2:123456789012:key/key"),
            ),
            ca=CA(
                stack_name="ca",
                mode=CAMode.SELF_SIGNED,
                trust_anchor_arn=Arn(
                    "arn:aws:rolesanywhere:ap-southeast-2:123456789012:trust-anchor/ta"
                ),
            ),
        )
        assert state.is_initialized is True

    def test_state_json_roundtrip(self) -> None:
        original = State(
            namespace="test",
            region="ap-southeast-2",
            version="0.1.0",
            init=Init(
                stack_name="iam-ra-test-init",
                bucket_arn=Arn("arn:aws:s3:::test-bucket"),
                kms_key_arn=Arn("arn:aws:kms:ap-southeast-2:123456789012:key/test-key"),
            ),
            ca=CA(
                stack_name="iam-ra-test-rootca",
                mode=CAMode.SELF_SIGNED,
                trust_anchor_arn=Arn(
                    "arn:aws:rolesanywhere:ap-southeast-2:123456789012:trust-anchor/ta-123"
                ),
            ),
            roles={
                "admin": Role(
                    stack_name="iam-ra-test-role-admin",
                    role_arn=Arn("arn:aws:iam::123456789012:role/iam-ra-test-admin"),
                    profile_arn=Arn(
                        "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/p-123"
                    ),
                    policies=(Arn("arn:aws:iam::aws:policy/AdministratorAccess"),),
                )
            },
            hosts={
                "web1": Host(
                    stack_name="iam-ra-test-host-web1",
                    hostname="web1",
                    role_name="admin",
                    certificate_secret_arn=Arn(
                        "arn:aws:secretsmanager:ap-southeast-2:123456789012:secret:cert"
                    ),
                    private_key_secret_arn=Arn(
                        "arn:aws:secretsmanager:ap-southeast-2:123456789012:secret:key"
                    ),
                )
            },
        )

        # Serialize and deserialize
        json_str = original.to_json()
        restored = State.from_json(json_str)

        # Verify all fields
        assert restored.namespace == original.namespace
        assert restored.region == original.region
        assert restored.version == original.version
        assert restored.is_initialized is True

        assert restored.init is not None
        assert restored.init.stack_name == original.init.stack_name
        assert isinstance(restored.init.bucket_arn, Arn)

        assert restored.ca is not None
        assert restored.ca.mode == CAMode.SELF_SIGNED

        assert "admin" in restored.roles
        assert isinstance(restored.roles["admin"].role_arn, Arn)
        assert len(restored.roles["admin"].policies) == 1

        assert "web1" in restored.hosts
        assert restored.hosts["web1"].hostname == "web1"

    def test_state_json_is_valid(self) -> None:
        state = State(namespace="test", region="us-east-1", version="1.0.0")
        json_str = state.to_json()

        # Should be valid JSON
        data = json.loads(json_str)

        assert data["namespace"] == "test"
        assert data["region"] == "us-east-1"
        assert data["init"] is None
        assert data["ca"] is None
