"""Template and SAM CLI helpers for IAM Roles Anywhere CLI."""

import subprocess
import tempfile
from importlib import resources
from pathlib import Path


def get_cloudformation_path() -> Path:
    """
    Get the path to the bundled CloudFormation templates.

    Returns:
        Path to the cloudformation directory within the package.
    """
    # Use importlib.resources to get the path to package data
    # This works whether installed as a package or run from source
    with resources.as_file(
        resources.files("iam_ra_cli.data") / "cloudformation"
    ) as cfn_path:
        # Return a copy of the path that persists after the context manager
        return Path(cfn_path)


def get_template_path(template_name: str) -> Path:
    """
    Get the path to a specific CloudFormation template.

    Args:
        template_name: Name of the template file (e.g., "account-rootca-stack.yaml")

    Returns:
        Path to the template file.
    """
    return get_cloudformation_path() / template_name


class SAMRunner:
    """
    Helper class to run SAM CLI commands with proper configuration.

    Uses the bundled CloudFormation templates and configures SAM to use
    a temporary build directory (avoiding writes to the Nix store).
    """

    def __init__(
        self,
        region: str,
        profile: str | None = None,
        build_dir: Path | None = None,
    ):
        """
        Initialize SAM runner.

        Args:
            region: AWS region for deployment
            profile: Optional AWS profile name
            build_dir: Optional build directory (defaults to temp dir)
        """
        self.region = region
        self.profile = profile
        self.cfn_path = get_cloudformation_path()

        # Use provided build_dir or create a temp directory
        if build_dir:
            self.build_dir = build_dir
            self._temp_dir = None
        else:
            self._temp_dir = tempfile.mkdtemp(prefix="iam-ra-sam-")
            self.build_dir = Path(self._temp_dir)

    def _base_args(self) -> list[str]:
        """Get base SAM CLI arguments."""
        args = [
            "--region",
            self.region,
            "--base-dir",
            str(self.cfn_path),
            "--build-dir",
            str(self.build_dir / "build"),
            "--cache-dir",
            str(self.build_dir / "cache"),
        ]
        if self.profile:
            args.extend(["--profile", self.profile])
        return args

    def build(
        self,
        template: str,
        use_container: bool = False,
    ) -> subprocess.CompletedProcess:
        """
        Run sam build for a template.

        Args:
            template: Template filename (e.g., "account-iamra-stack.yaml")
            use_container: Whether to use Docker for building

        Returns:
            CompletedProcess result
        """
        template_path = self.cfn_path / template

        cmd = [
            "sam",
            "build",
            "--template-file",
            str(template_path),
            "--build-dir",
            str(self.build_dir / "build"),
            "--cache-dir",
            str(self.build_dir / "cache"),
            "--base-dir",
            str(self.cfn_path),
        ]

        if use_container:
            cmd.append("--use-container")

        return subprocess.run(cmd, check=True, capture_output=True, text=True)

    def deploy(
        self,
        template: str,
        stack_name: str,
        parameter_overrides: dict[str, str] | None = None,
        capabilities: list[str] | None = None,
        no_confirm: bool = True,
        tags: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess:
        """
        Run sam deploy for a template.

        Args:
            template: Template filename (e.g., "account-iamra-stack.yaml")
            stack_name: CloudFormation stack name
            parameter_overrides: Dict of parameter name -> value
            capabilities: List of capabilities (default: CAPABILITY_IAM, CAPABILITY_AUTO_EXPAND)
            no_confirm: Skip confirmation prompts
            tags: Dict of tag name -> value

        Returns:
            CompletedProcess result
        """
        # Use the built template if it exists, otherwise use source
        built_template = self.build_dir / "build" / "template.yaml"
        if built_template.exists():
            template_path = built_template
        else:
            template_path = self.cfn_path / template

        cmd = [
            "sam",
            "deploy",
            "--template-file",
            str(template_path),
            "--stack-name",
            stack_name,
            "--region",
            self.region,
        ]

        if self.profile:
            cmd.extend(["--profile", self.profile])

        # Capabilities
        caps = capabilities or ["CAPABILITY_IAM", "CAPABILITY_AUTO_EXPAND"]
        cmd.extend(["--capabilities"] + caps)

        # Parameter overrides
        if parameter_overrides:
            overrides = " ".join(f"{k}={v}" for k, v in parameter_overrides.items())
            cmd.extend(["--parameter-overrides", overrides])

        # Tags
        if tags:
            tag_list = " ".join(f"{k}={v}" for k, v in tags.items())
            cmd.extend(["--tags", tag_list])

        if no_confirm:
            cmd.append("--no-confirm-changeset")
            cmd.append("--no-fail-on-empty-changeset")

        return subprocess.run(cmd, check=True, capture_output=True, text=True)

    def build_and_deploy(
        self,
        template: str,
        stack_name: str,
        parameter_overrides: dict[str, str] | None = None,
        capabilities: list[str] | None = None,
        no_confirm: bool = True,
        tags: dict[str, str] | None = None,
        use_container: bool = False,
    ) -> subprocess.CompletedProcess:
        """
        Build and deploy a SAM template in one step.

        Args:
            template: Template filename
            stack_name: CloudFormation stack name
            parameter_overrides: Dict of parameter name -> value
            capabilities: List of capabilities
            no_confirm: Skip confirmation prompts
            tags: Dict of tag name -> value
            use_container: Whether to use Docker for building

        Returns:
            CompletedProcess result from deploy
        """
        # Build first (only for templates that need it - those with Lambda)
        self.build(template, use_container=use_container)

        # Then deploy
        return self.deploy(
            template=template,
            stack_name=stack_name,
            parameter_overrides=parameter_overrides,
            capabilities=capabilities,
            no_confirm=no_confirm,
            tags=tags,
        )

    def cleanup(self):
        """Clean up temporary build directory if we created one."""
        if self._temp_dir:
            import shutil

            shutil.rmtree(self._temp_dir, ignore_errors=True)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()
        return False
