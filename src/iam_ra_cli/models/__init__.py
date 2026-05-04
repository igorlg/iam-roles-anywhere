"""IAM Roles Anywhere data models.

Pure data structures with JSON serialization. No storage coupling.
"""

from __future__ import annotations

import json
from contextlib import suppress
from dataclasses import asdict, dataclass, field
from enum import Enum, StrEnum
from typing import Any, Self


class Arn(str):
    """AWS ARN - a string subclass with parsed component access."""

    def __new__(cls, value: str) -> Self:
        parts = value.split(":")
        if len(parts) < 6 or parts[0] != "arn":
            raise ValueError(f"Invalid ARN: {value}")
        return super().__new__(cls, value)

    @property
    def arn_partition(self) -> str:
        return self.split(":")[1]

    @property
    def service(self) -> str:
        return self.split(":")[2]

    @property
    def region(self) -> str:
        return self.split(":")[3]

    @property
    def account(self) -> str:
        return self.split(":")[4]

    @property
    def resource(self) -> str:
        return ":".join(self.split(":")[5:])

    @property
    def resource_type(self) -> str:
        res = self.resource
        if "/" in res:
            return res.split("/")[0]
        if ":" in res:
            return res.split(":")[0]
        return res

    @property
    def resource_id(self) -> str:
        res = self.resource
        if "/" in res:
            return "/".join(res.split("/")[1:])
        if ":" in res:
            return ":".join(res.split(":")[1:])
        return res


class CAMode(StrEnum):
    """Certificate Authority mode."""

    SELF_SIGNED = "self-signed"
    PCA_NEW = "pca-new"
    PCA_EXISTING = "pca-existing"


@dataclass(frozen=True)
class Init:
    """Bootstrap resources."""

    stack_name: str
    bucket_arn: Arn
    kms_key_arn: Arn


@dataclass(frozen=True)
class NamespaceInfo:
    """Namespace-level metadata (v3).

    Populated at `iam-ra init` time from the AWS caller identity + region.
    Stored alongside the other state so later commands can display/validate
    the namespace's AWS account context (e.g. flag "wrong credentials" when
    the active profile's account doesn't match).
    """

    account_id: str
    region: str


@dataclass(frozen=True)
class CA:
    """Certificate Authority configuration.

    v3 adds `account_id` (optional for back-compat with v2 state on-disk)
    so we can surface the account a CA belongs to without re-parsing the
    trust anchor ARN everywhere. Migration from v2 derives it from
    trust_anchor_arn.account.
    """

    stack_name: str
    mode: CAMode
    trust_anchor_arn: Arn
    pca_arn: Arn | None = None
    account_id: str | None = None


@dataclass(frozen=True)
class Role:
    """IAM Role with Roles Anywhere profile.

    The scope field determines which CA/Trust Anchor this role
    is associated with. Certs signed by a scope's CA can only
    assume roles within that same scope.
    """

    stack_name: str
    role_arn: Arn
    profile_arn: Arn
    policies: tuple[Arn, ...] = ()
    scope: str = "default"


@dataclass(frozen=True)
class Host:
    """Onboarded host with certificate.

    v3: a single host can hold multiple roles under the same cert (scenario
    2 from the multi-identity plan). All roles must share the same scope
    (enforced by the onboard / add-role workflows, not the dataclass).

    `scope` is explicit in v3 - in v2 it was inferred from the single
    role's scope. Making it explicit means a host's identity (scope + cert)
    is self-describing without a cross-reference to the role table.
    """

    stack_name: str
    hostname: str
    role_names: tuple[str, ...]
    certificate_secret_arn: Arn
    private_key_secret_arn: Arn
    scope: str = "default"


@dataclass(frozen=True)
class K8sCluster:
    """Kubernetes cluster configured for IAM Roles Anywhere.

    Represents a K8s cluster where workloads can be onboarded.
    Per-namespace CA setup is handled by scopes, not by the cluster.
    """

    name: str


@dataclass(frozen=True)
class K8sWorkload:
    """Kubernetes workload onboarded to IAM Roles Anywhere.

    Represents an application/service in a K8s cluster that uses
    IAM Roles Anywhere for AWS credentials via cert-manager certificates.
    """

    name: str
    cluster_name: str
    role_name: str
    namespace: str = "default"


@dataclass
class State:
    """Complete IAM Roles Anywhere state for a namespace.

    v2: CAs are per-scope (cas dict) instead of a single global CA.
    v3: Hosts can hold multiple roles (role_names tuple) and carry an
    explicit scope. NamespaceInfo tracks the namespace's AWS account +
    region so commands can display/validate the account context.
    """

    namespace: str
    region: str
    version: str
    namespace_info: NamespaceInfo | None = None
    init: Init | None = None
    cas: dict[str, CA] = field(default_factory=dict)
    roles: dict[str, Role] = field(default_factory=dict)
    hosts: dict[str, Host] = field(default_factory=dict)
    k8s_clusters: dict[str, K8sCluster] = field(default_factory=dict)
    k8s_workloads: dict[str, K8sWorkload] = field(default_factory=dict)

    @property
    def is_initialized(self) -> bool:
        return self.init is not None

    @property
    def ca(self) -> CA | None:
        """Backward-compat: return the default scope CA, or None."""
        return self.cas.get("default")

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)

    @classmethod
    def from_json(cls, data: str) -> Self:
        raw = json.loads(data)

        # MIGRATION_SHIM (remove in v5.0): v1 -> v2 conversion of single 'ca'
        # field to 'cas["default"]' dict. v1 state shipped prior to per-scope
        # CAs (see git history: commit ed325b7, "feat: scoped CAs").
        if "ca" in raw and "cas" not in raw:
            ca_val = raw.pop("ca")
            raw["cas"] = {"default": ca_val} if ca_val is not None else {}
        elif "ca" in raw:
            # v2+ state that somehow has both -- ignore legacy 'ca'
            raw.pop("ca")

        # MIGRATION_SHIM (remove in v5.0): v2 -> v3 conversion of
        # Host.role_name (str) to Host.role_names (tuple[str, ...]), and
        # derivation of Host.scope from the role's scope.
        roles_raw = raw.get("roles", {})
        for host_raw in raw.get("hosts", {}).values():
            if "role_name" in host_raw and "role_names" not in host_raw:
                role_name = host_raw.pop("role_name")
                host_raw["role_names"] = [role_name]
                if "scope" not in host_raw:
                    role = roles_raw.get(role_name, {})
                    host_raw["scope"] = role.get("scope", "default")

        # MIGRATION_SHIM (remove in v5.0): v2 -> v3 backfill CA.account_id
        # from trust_anchor_arn.account. ARNs already carry the account; we
        # promote it to a first-class field for visibility.
        for ca_raw in raw.get("cas", {}).values():
            if "account_id" not in ca_raw and "trust_anchor_arn" in ca_raw:
                # Malformed ARN -> leave account_id unset.
                with suppress(ValueError):
                    ca_raw["account_id"] = Arn(ca_raw["trust_anchor_arn"]).account

        # MIGRATION_SHIM (remove in v5.0): v2 -> v3 backfill NamespaceInfo
        # from init.kms_key_arn.account + region. The bucket ARN is not a
        # useful source because S3 bucket ARNs omit the account field
        # (arn:aws:s3:::bucket-name); the KMS key ARN always has it.
        # If init is absent we cannot derive the account, so namespace_info
        # stays None.
        if "namespace_info" not in raw or raw.get("namespace_info") is None:
            init_raw = raw.get("init")
            if init_raw is not None and "kms_key_arn" in init_raw:
                # Malformed ARN -> leave namespace_info as None.
                with suppress(ValueError):
                    account_id = Arn(init_raw["kms_key_arn"]).account
                    if account_id:
                        raw["namespace_info"] = {
                            "account_id": account_id,
                            "region": raw.get("region", ""),
                        }

        return _from_dict(cls, raw)


def _from_dict(cls: type, data: Any) -> Any:
    """Reconstruct typed dataclass from dict. Handles Arn, Enum, Optional, nested."""
    import types
    from dataclasses import fields, is_dataclass
    from typing import get_args, get_origin, get_type_hints

    if data is None:
        return None

    origin = get_origin(cls)

    # Handle Union (X | None)
    if origin is types.UnionType:
        args = [a for a in get_args(cls) if a is not type(None)]
        return _from_dict(args[0], data) if args else None

    # Arn (str subclass)
    if cls is Arn or (isinstance(cls, type) and issubclass(cls, Arn)):
        return Arn(data)

    # Enum
    if isinstance(cls, type) and issubclass(cls, Enum):
        return cls(data)

    # Dataclass
    if is_dataclass(cls):
        hints = get_type_hints(cls)
        kwargs = {}
        for f in fields(cls):
            if f.name in data:
                kwargs[f.name] = _from_dict(hints[f.name], data[f.name])
        return cls(**kwargs)

    # dict[K, V]
    if origin is dict:
        _, val_type = get_args(cls)
        return {k: _from_dict(val_type, v) for k, v in data.items()}

    # list[X]
    if origin is list:
        (item_type,) = get_args(cls)
        return [_from_dict(item_type, v) for v in data]

    # tuple[X, ...]
    if origin is tuple:
        tuple_args = get_args(cls)
        if len(tuple_args) == 2 and tuple_args[1] is ...:
            return tuple(_from_dict(tuple_args[0], v) for v in data)
        return tuple(_from_dict(t, v) for t, v in zip(tuple_args, data))

    return data
