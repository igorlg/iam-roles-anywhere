"""Pre-flight validation helpers for workflow entry points.

Cross-cutting checks that many workflows want to run before doing any
AWS / CFN work. Centralised here so the same guard logic appears
exactly once.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from iam_ra_cli.lib.errors import AccountMismatchError
from iam_ra_cli.lib.result import Err, Ok, Result

if TYPE_CHECKING:
    from iam_ra_cli.lib.aws import AwsContext
    from iam_ra_cli.models import State


def check_account_matches_namespace(
    ctx: AwsContext, state: State
) -> Result[None, AccountMismatchError]:
    """Verify the active AWS credentials are for the namespace's account.

    Every namespace is pinned to a single AWS account (SSM/S3/KMS can't
    span accounts). Running state-mutating commands with credentials for
    a different account either fails late or silently targets the wrong
    account. This check fails fast at workflow entry time.

    Returns:
        Ok(None) when:
            - state.namespace_info is None (pre-v3 state, no account on
              record - we can't check, skip rather than fail),
            - or when the account IDs match.
        Err(AccountMismatchError) with both account IDs so the caller
        can surface a clear "switch profile" message.

    Note: `state.namespace_info` is populated at `iam-ra init` time for
    fresh namespaces and backfilled on-read for v2-era state (derived
    from init.kms_key_arn.account). Only state that pre-dates the init
    step - hypothetical - would bypass this check.
    """
    if state.namespace_info is None:
        return Ok(None)

    expected = state.namespace_info.account_id
    actual = ctx.account_id
    if expected != actual:
        return Err(
            AccountMismatchError(
                namespace=state.namespace,
                expected_account_id=expected,
                actual_account_id=actual,
            )
        )

    return Ok(None)
