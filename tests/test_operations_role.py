"""Tests for operations/role.py - Role operations with scope support.

Tests verify:
- TrustAnchorArn parameter is passed to CloudFormation
- scope tag is included in stack tags
- stack naming is unchanged
"""

from unittest.mock import MagicMock, patch

import pytest

from iam_ra_cli.lib.aws import AwsContext
from iam_ra_cli.lib.result import Ok
from iam_ra_cli.models import Arn
from iam_ra_cli.operations.role import _stack_name, create_role


class TestStackName:
    """Stack naming should be unchanged by scope work."""

    def test_stack_name_format(self) -> None:
        assert _stack_name("test", "admin") == "iam-ra-test-role-admin"

    def test_stack_name_with_hyphens(self) -> None:
        assert _stack_name("my-ns", "my-role") == "iam-ra-my-ns-role-my-role"


class TestCreateRoleOperation:
    """Tests for create_role operation passing TrustAnchorArn to CFN."""

    def test_passes_trust_anchor_arn_as_cfn_parameter(self) -> None:
        """TrustAnchorArn must be passed as a CloudFormation parameter."""
        trust_anchor_arn = "arn:aws:rolesanywhere:ap-southeast-2:123456789012:trust-anchor/ta-123"

        mock_outputs = {
            "RoleArn": "arn:aws:iam::123456789012:role/iam-ra-test-myrole",
            "ProfileArn": "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/p-myrole",
        }

        with patch(
            "iam_ra_cli.operations.role.deploy_stack", return_value=Ok(mock_outputs)
        ) as mock_deploy:
            ctx = MagicMock(spec=AwsContext)
            result = create_role(
                ctx,
                "test",
                "myrole",
                trust_anchor_arn=trust_anchor_arn,
            )

            assert isinstance(result, Ok)

            # Check deploy_stack was called with TrustAnchorArn in parameters
            mock_deploy.assert_called_once()
            call_kwargs = mock_deploy.call_args.kwargs
            params = call_kwargs["parameters"]
            assert "TrustAnchorArn" in params
            assert params["TrustAnchorArn"] == trust_anchor_arn

    def test_passes_scope_tag(self) -> None:
        """Scope should be included as a tag on the CFN stack."""
        trust_anchor_arn = "arn:aws:rolesanywhere:ap-southeast-2:123456789012:trust-anchor/ta-123"

        mock_outputs = {
            "RoleArn": "arn:aws:iam::123456789012:role/iam-ra-test-myrole",
            "ProfileArn": "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/p-myrole",
        }

        with patch(
            "iam_ra_cli.operations.role.deploy_stack", return_value=Ok(mock_outputs)
        ) as mock_deploy:
            ctx = MagicMock(spec=AwsContext)
            result = create_role(
                ctx,
                "test",
                "myrole",
                trust_anchor_arn=trust_anchor_arn,
                scope="cert-manager",
            )

            assert isinstance(result, Ok)

            call_kwargs = mock_deploy.call_args.kwargs
            tags = call_kwargs["tags"]
            assert tags["iam-ra:scope"] == "cert-manager"

    def test_default_scope_tag_when_not_specified(self) -> None:
        """When scope is not explicitly given, tag should be 'default'."""
        trust_anchor_arn = "arn:aws:rolesanywhere:ap-southeast-2:123456789012:trust-anchor/ta-123"

        mock_outputs = {
            "RoleArn": "arn:aws:iam::123456789012:role/iam-ra-test-myrole",
            "ProfileArn": "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/p-myrole",
        }

        with patch(
            "iam_ra_cli.operations.role.deploy_stack", return_value=Ok(mock_outputs)
        ) as mock_deploy:
            ctx = MagicMock(spec=AwsContext)
            result = create_role(
                ctx,
                "test",
                "myrole",
                trust_anchor_arn=trust_anchor_arn,
            )

            assert isinstance(result, Ok)

            call_kwargs = mock_deploy.call_args.kwargs
            tags = call_kwargs["tags"]
            assert tags["iam-ra:scope"] == "default"

    def test_policies_forwarded_to_cfn(self) -> None:
        """PolicyArns should still be passed through when provided."""
        trust_anchor_arn = "arn:aws:rolesanywhere:ap-southeast-2:123456789012:trust-anchor/ta-123"
        policies = ["arn:aws:iam::aws:policy/ReadOnlyAccess"]

        mock_outputs = {
            "RoleArn": "arn:aws:iam::123456789012:role/iam-ra-test-myrole",
            "ProfileArn": "arn:aws:rolesanywhere:ap-southeast-2:123456789012:profile/p-myrole",
        }

        with patch(
            "iam_ra_cli.operations.role.deploy_stack", return_value=Ok(mock_outputs)
        ) as mock_deploy:
            ctx = MagicMock(spec=AwsContext)
            result = create_role(
                ctx,
                "test",
                "myrole",
                policies=policies,
                trust_anchor_arn=trust_anchor_arn,
            )

            assert isinstance(result, Ok)

            call_kwargs = mock_deploy.call_args.kwargs
            params = call_kwargs["parameters"]
            assert params["PolicyArns"] == "arn:aws:iam::aws:policy/ReadOnlyAccess"
            assert params["TrustAnchorArn"] == trust_anchor_arn
