"""Tests for the role trust policy's per-host restriction.

These assert on the CloudFormation template itself rather than on a deployed
stack, because the property that matters is what the *policy document* says.
Getting a trust policy wrong fails in one of two bad ways: deny everything, or
protect nothing.

Two facts from the IAM Roles Anywhere documentation drive the design:

* IAM Roles Anywhere populates ``aws:PrincipalTag/x509Subject/CN`` from the
  authenticating certificate by default, so no attribute mapping is needed.
* A ``StringLike`` condition on an **absent** tag evaluates FALSE. So the
  condition must only be emitted when the operator opts in - otherwise anyone
  whose profile drops the tag would silently lose access on upgrade.
"""

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

TEMPLATE = Path("src/iam_ra_cli/data/cloudformation/role.yaml")


class _CfnLoader(yaml.SafeLoader):
    """SafeLoader that tolerates CloudFormation short-form intrinsics."""


def _intrinsic(loader: Any, suffix: str, node: Any) -> Any:
    name = f"Fn::{suffix}" if suffix not in ("Ref", "Condition") else suffix
    if isinstance(node, yaml.ScalarNode):
        return {name: loader.construct_scalar(node)}
    if isinstance(node, yaml.SequenceNode):
        return {name: loader.construct_sequence(node, deep=True)}
    return {name: loader.construct_mapping(node, deep=True)}


_CfnLoader.add_multi_constructor("!", _intrinsic)


@pytest.fixture(scope="module")
def template() -> dict[str, Any]:
    return yaml.load(TEMPLATE.read_text(), Loader=_CfnLoader)


@pytest.fixture(scope="module")
def trust_condition(template: dict[str, Any]) -> dict[str, Any]:
    statement = template["Resources"]["Role"]["Properties"]["AssumeRolePolicyDocument"][
        "Statement"
    ][0]
    return statement["Condition"]


class TestParameter:
    def test_defaults_to_unrestricted(self, template: dict[str, Any]) -> None:
        """The default must preserve historical behaviour exactly."""
        assert template["Parameters"]["AllowedSubjectCN"]["Default"] == "*"

    def test_condition_gates_on_the_parameter(self, template: dict[str, Any]) -> None:
        assert "RestrictSubjectCN" in template["Conditions"]


class TestTrustPolicyShape:
    def test_condition_is_an_if_on_restrict(self, trust_condition: dict[str, Any]) -> None:
        """It must be an Fn::If, not an unconditional condition block.

        Emitting a wildcard StringLike by default would add a dependency on the
        principal tag being present, turning an absent tag into a denial.
        """
        assert "Fn::If" in trust_condition
        assert trust_condition["Fn::If"][0] == "RestrictSubjectCN"

    def test_unrestricted_branch_has_only_the_trust_anchor(
        self, trust_condition: dict[str, Any]
    ) -> None:
        _name, _restricted, unrestricted = trust_condition["Fn::If"]

        assert set(unrestricted) == {"ArnEquals"}
        assert "aws:SourceArn" in unrestricted["ArnEquals"]

    def test_unrestricted_branch_mentions_no_principal_tag(
        self, trust_condition: dict[str, Any]
    ) -> None:
        """The whole point of the Fn::If: no tag dependency when not opted in."""
        _name, _restricted, unrestricted = trust_condition["Fn::If"]

        assert "PrincipalTag" not in json.dumps(unrestricted)

    def test_restricted_branch_keeps_the_trust_anchor_condition(
        self, trust_condition: dict[str, Any]
    ) -> None:
        """Narrowing by host must ADD to the trust-anchor pin, not replace it -
        dropping aws:SourceArn would reintroduce a confused-deputy exposure."""
        _name, restricted, _unrestricted = trust_condition["Fn::If"]

        assert "ArnEquals" in restricted
        assert "aws:SourceArn" in restricted["ArnEquals"]

    def test_restricted_branch_matches_the_subject_cn(
        self, trust_condition: dict[str, Any]
    ) -> None:
        _name, restricted, _unrestricted = trust_condition["Fn::If"]

        assert "StringLike" in restricted
        assert "aws:PrincipalTag/x509Subject/CN" in restricted["StringLike"]
        assert restricted["StringLike"]["aws:PrincipalTag/x509Subject/CN"] == {
            "Ref": "AllowedSubjectCN"
        }

    def test_uses_string_like_so_wildcards_work(
        self, trust_condition: dict[str, Any]
    ) -> None:
        """StringEquals would make 'web-*' a literal, silently matching nothing."""
        _name, restricted, _unrestricted = trust_condition["Fn::If"]

        assert "StringEquals" not in restricted

    def test_still_grants_tag_session(self, template: dict[str, Any]) -> None:
        """sts:TagSession is what allows the principal tags to be set at all;
        without it the x509Subject condition could never match."""
        statement = template["Resources"]["Role"]["Properties"][
            "AssumeRolePolicyDocument"
        ]["Statement"][0]

        assert "sts:TagSession" in statement["Action"]

    def test_profile_sets_no_attribute_mappings(self, template: dict[str, Any]) -> None:
        """A custom attributeMappings omitting the Subject CN specifier would
        drop aws:PrincipalTag/x509Subject/CN, and a StringLike on an absent tag
        evaluates false - so a restricted role would become unassumable."""
        profile = template["Resources"]["Profile"]["Properties"]

        assert "AttributeMappings" not in profile


class TestTemplateIsValid:
    def test_cfn_lint_passes(self) -> None:
        result = subprocess.run(
            ["cfn-lint", str(TEMPLATE)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stdout + result.stderr
