"""Status workflow - get current state."""

from dataclasses import dataclass

from iam_ra_cli.lib import state as state_module
from iam_ra_cli.lib.aws import AwsContext
from iam_ra_cli.lib.result import Err, Ok
from iam_ra_cli.models import CA, Host, Init, Role


@dataclass(frozen=True)
class Status:
    """Current status of a namespace.

    Never fails - returns empty/uninitialized status if not set up.
    """

    namespace: str
    region: str
    initialized: bool
    init: Init | None
    cas: dict[str, CA]
    roles: dict[str, Role]
    hosts: dict[str, Host]

    @property
    def ca(self) -> CA | None:
        """Backward-compat: return the default scope CA, or None."""
        return self.cas.get("default")


def get_status(ctx: AwsContext, namespace: str) -> Status:
    """Get current status. Never fails - returns uninitialized status if not set up."""
    match state_module.load(ctx.ssm, ctx.s3, namespace):
        case Err(_):
            # Error loading state - return uninitialized
            return Status(
                namespace=namespace,
                region=ctx.region,
                initialized=False,
                init=None,
                cas={},
                roles={},
                hosts={},
            )
        case Ok(None):
            # Not initialized
            return Status(
                namespace=namespace,
                region=ctx.region,
                initialized=False,
                init=None,
                cas={},
                roles={},
                hosts={},
            )
        case Ok(state) if state is not None:
            return Status(
                namespace=state.namespace,
                region=state.region,
                initialized=state.is_initialized,
                init=state.init,
                cas=state.cas,
                roles=state.roles,
                hosts=state.hosts,
            )

    # Fallback (should never reach here)
    return Status(
        namespace=namespace,
        region=ctx.region,
        initialized=False,
        init=None,
        cas={},
        roles={},
        hosts={},
    )
