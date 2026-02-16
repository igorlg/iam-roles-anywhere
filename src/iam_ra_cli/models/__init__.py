"""IAM Roles Anywhere data models.

Pure data structures with JSON serialization. No storage coupling.
"""

from __future__ import annotations

import json
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
class CA:
    """Certificate Authority configuration."""

    stack_name: str
    mode: CAMode
    trust_anchor_arn: Arn
    pca_arn: Arn | None = None


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
    """Onboarded host with certificate."""

    stack_name: str
    hostname: str
    role_name: str
    certificate_secret_arn: Arn
    private_key_secret_arn: Arn


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
    Roles belong to a scope via their scope field.
    """

    namespace: str
    region: str
    version: str
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
        # v1 → v2 migration: convert single 'ca' to 'cas["default"]'
        if "ca" in raw and "cas" not in raw:
            ca_val = raw.pop("ca")
            raw["cas"] = {"default": ca_val} if ca_val is not None else {}
        elif "ca" in raw:
            # v2 state that somehow has both -- ignore legacy 'ca'
            raw.pop("ca")
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
