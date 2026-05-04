"""Tests for the account-mismatch pre-flight helper.

A namespace owns a single AWS account (via its SSM parameter + S3 bucket +
KMS key). Every state-mutating command must run with AWS credentials for
that account; otherwise the command will either fail late (AWS denies
access) or succeed against the wrong account (data corruption).

The helper `check_account_matches_namespace` fails fast at workflow entry
time with a clear error pointing users at AWS_PROFILE / --profile as the
fix.
"""

from iam_ra_cli.lib.errors import AccountMismatchError
from iam_ra_cli.lib.result import Err, Ok
from iam_ra_cli.models import NamespaceInfo, State


class _FakeCtx:
    """Minimal stand-in for AwsContext - exposes just account_id."""

    def __init__(self, account_id: str) -> None:
        self.account_id = account_id


class TestCheckAccountMatch:
    def test_match_returns_ok(self) -> None:
        from iam_ra_cli.lib.preflight import check_account_matches_namespace

        ctx = _FakeCtx(account_id="123456789012")
        state = State(
            namespace="test",
            region="ap-southeast-2",
            version="3.0.0",
            namespace_info=NamespaceInfo(
                account_id="123456789012", region="ap-southeast-2"
            ),
        )

        result = check_account_matches_namespace(ctx, state)
        assert isinstance(result, Ok)

    def test_mismatch_returns_err_with_both_account_ids(self) -> None:
        from iam_ra_cli.lib.preflight import check_account_matches_namespace

        ctx = _FakeCtx(account_id="999999999999")
        state = State(
            namespace="work",
            region="ap-southeast-2",
            version="3.0.0",
            namespace_info=NamespaceInfo(
                account_id="123456789012", region="ap-southeast-2"
            ),
        )

        result = check_account_matches_namespace(ctx, state)

        assert isinstance(result, Err)
        assert isinstance(result.error, AccountMismatchError)
        assert result.error.namespace == "work"
        assert result.error.expected_account_id == "123456789012"
        assert result.error.actual_account_id == "999999999999"

    def test_state_without_namespace_info_is_ok(self) -> None:
        """Pre-v3 state (or freshly-initialised state with no info yet) has
        no namespace_info. We skip the check rather than failing - the
        check is opportunistic, not mandatory.
        """
        from iam_ra_cli.lib.preflight import check_account_matches_namespace

        ctx = _FakeCtx(account_id="123456789012")
        state = State(
            namespace="legacy",
            region="ap-southeast-2",
            version="2.0.0",
            namespace_info=None,
        )

        result = check_account_matches_namespace(ctx, state)
        assert isinstance(result, Ok)
