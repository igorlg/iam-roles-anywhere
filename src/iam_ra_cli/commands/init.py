"""Init command - bootstrap IAM Roles Anywhere infrastructure."""

import click

from iam_ra_cli import __version__
from iam_ra_cli.lib import cfn, crypto, paths, state
from iam_ra_cli.lib.storage import s3
from iam_ra_cli.lib.templates import get_template_path
from iam_ra_cli.models import Arn, CA, CAMode, Init, State


DEFAULT_NAMESPACE = "default"
DEFAULT_REGION = "ap-southeast-2"

INIT_TEMPLATE = "init.yaml"
ROOTCA_SELF_SIGNED_TEMPLATE = "rootca-self-signed.yaml"
ROOTCA_PCA_NEW_TEMPLATE = "rootca-pca-new.yaml"
ROOTCA_PCA_EXISTING_TEMPLATE = "rootca-pca-existing.yaml"


def _stack_name(namespace: str, suffix: str) -> str:
    """Generate stack name from namespace."""
    return f"iam-ra-{namespace}-{suffix}"


def _load_template(name: str) -> str:
    """Load CloudFormation template body."""
    path = get_template_path(name)
    return path.read_text()


@click.command()
@click.option(
    "--namespace",
    "-n",
    default=DEFAULT_NAMESPACE,
    show_default=True,
    help="Namespace identifier for this deployment",
)
@click.option(
    "--region",
    "-r",
    default=DEFAULT_REGION,
    show_default=True,
    help="AWS region",
)
@click.option(
    "--profile",
    "-p",
    default=None,
    help="AWS profile",
)
@click.option(
    "--ca-mode",
    type=click.Choice(["self-signed", "pca-new", "pca-existing"]),
    default="self-signed",
    show_default=True,
    help="Certificate Authority mode",
)
@click.option(
    "--pca-arn",
    default=None,
    help="Existing ACM PCA ARN (required for pca-existing mode)",
)
@click.option(
    "--ca-validity-years",
    default=10,
    show_default=True,
    help="CA certificate validity (self-signed mode)",
)
@click.option(
    "--force",
    is_flag=True,
    help="Force reinitialization even if already initialized",
)
def init(
    namespace: str,
    region: str,
    profile: str | None,
    ca_mode: str,
    pca_arn: str | None,
    ca_validity_years: int,
    force: bool,
) -> None:
    """Initialize IAM Roles Anywhere infrastructure.

    Deploys the init stack (S3, KMS, Lambdas) and CA stack (Trust Anchor).

    \b
    CA Modes:
      self-signed   - Generate a self-signed CA locally (default, simplest)
      pca-new       - Create a new AWS Private CA
      pca-existing  - Use an existing AWS Private CA (requires --pca-arn)

    \b
    Examples:
      iam-ra init
      iam-ra init --namespace prod --region us-east-1
      iam-ra init --ca-mode pca-existing --pca-arn arn:aws:acm-pca:...
    """
    # Validate options
    mode = CAMode(ca_mode)
    if mode == CAMode.PCA_EXISTING and not pca_arn:
        raise click.ClickException("--pca-arn required for pca-existing mode")

    # Check if already initialized
    existing = state.load(namespace, region, profile)
    if existing and existing.is_initialized and not force:
        assert existing.init is not None
        assert existing.ca is not None
        click.echo(f"Namespace '{namespace}' is already initialized.")
        click.echo(f"  Init stack:  {existing.init.stack_name}")
        click.echo(f"  CA stack:    {existing.ca.stack_name}")
        click.echo(f"  CA mode:     {existing.ca.mode.value}")
        click.echo()
        click.echo("Use --force to reinitialize.")
        return

    click.echo(f"Initializing IAM Roles Anywhere")
    click.echo(f"  Namespace: {namespace}")
    click.echo(f"  Region:    {region}")
    click.echo(f"  CA mode:   {ca_mode}")
    click.echo()

    # Ensure local directories exist
    paths.config_dir().mkdir(parents=True, exist_ok=True)
    paths.data_dir().mkdir(parents=True, exist_ok=True)

    # Step 1: Deploy init stack (uses SAM transform, needs CAPABILITY_AUTO_EXPAND)
    init_stack = _stack_name(namespace, "init")
    click.echo(f"[1/2] Deploying init stack: {init_stack}")

    init_template = _load_template(INIT_TEMPLATE)
    init_outputs = cfn.deploy(
        stack_name=init_stack,
        template_body=init_template,
        region=region,
        profile=profile,
        parameters={"Namespace": namespace},
        tags={"iam-ra:namespace": namespace},
        capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM", "CAPABILITY_AUTO_EXPAND"],
    )

    bucket_arn = Arn(init_outputs["BucketArn"])
    bucket_name = init_outputs["BucketName"]
    kms_key_arn = Arn(init_outputs["KMSKeyArn"])

    click.echo(f"       Bucket: {bucket_name}")
    click.echo(f"       KMS:    {kms_key_arn}")

    # Build initial state (without CA yet)
    new_state = State(
        namespace=namespace,
        region=region,
        version=__version__,
        init=Init(
            stack_name=init_stack,
            bucket_arn=bucket_arn,
            kms_key_arn=kms_key_arn,
        ),
    )

    # Step 2: Deploy CA stack based on mode
    ca_stack = _stack_name(namespace, "rootca")
    click.echo(f"[2/2] Deploying CA stack: {ca_stack}")

    trust_anchor_arn: Arn
    ca_state: CA

    if mode == CAMode.SELF_SIGNED:
        # Generate CA locally and upload to S3
        click.echo("       Generating self-signed CA...")
        ca_keypair = crypto.generate_ca(
            common_name=f"IAM Roles Anywhere CA ({namespace})",
            validity_years=ca_validity_years,
        )

        # Upload CA cert to S3 (key only stored locally, never in cloud)
        ca_s3_key = f"{namespace}/ca/certificate.pem"
        s3.write(bucket_name, ca_s3_key, ca_keypair.certificate, region, profile)
        click.echo(f"       Uploaded CA cert to s3://{bucket_name}/{ca_s3_key}")

        # Also save CA key locally for future host cert generation
        ca_key_path = paths.data_dir() / namespace / "ca-private-key.pem"
        ca_key_path.parent.mkdir(parents=True, exist_ok=True)
        ca_key_path.write_text(ca_keypair.private_key)
        ca_key_path.chmod(0o600)
        click.echo(f"       Saved CA key to {ca_key_path}")

        # Deploy rootca-self-signed stack
        ca_template = _load_template(ROOTCA_SELF_SIGNED_TEMPLATE)
        ca_outputs = cfn.deploy(
            stack_name=ca_stack,
            template_body=ca_template,
            region=region,
            profile=profile,
            parameters={
                "Namespace": namespace,
                "CACertificateS3Key": ca_s3_key,
            },
            tags={"iam-ra:namespace": namespace},
        )

        trust_anchor_arn = Arn(ca_outputs["TrustAnchorArn"])
        ca_state = CA(
            stack_name=ca_stack,
            mode=CAMode.SELF_SIGNED,
            trust_anchor_arn=trust_anchor_arn,
        )

    elif mode == CAMode.PCA_NEW:
        # Deploy rootca-pca-new stack
        ca_template = _load_template(ROOTCA_PCA_NEW_TEMPLATE)
        ca_outputs = cfn.deploy(
            stack_name=ca_stack,
            template_body=ca_template,
            region=region,
            profile=profile,
            parameters={"Namespace": namespace},
            tags={"iam-ra:namespace": namespace},
        )

        trust_anchor_arn = Arn(ca_outputs["TrustAnchorArn"])
        pca_created_arn = Arn(ca_outputs["PCAArn"])
        ca_state = CA(
            stack_name=ca_stack,
            mode=CAMode.PCA_NEW,
            trust_anchor_arn=trust_anchor_arn,
            pca_arn=pca_created_arn,
        )

    else:  # PCA_EXISTING - pca_arn is guaranteed non-None by validation above
        assert pca_arn is not None
        # Deploy rootca-pca-existing stack
        ca_template = _load_template(ROOTCA_PCA_EXISTING_TEMPLATE)
        ca_outputs = cfn.deploy(
            stack_name=ca_stack,
            template_body=ca_template,
            region=region,
            profile=profile,
            parameters={
                "Namespace": namespace,
                "PCAArn": pca_arn,
            },
            tags={"iam-ra:namespace": namespace},
        )

        trust_anchor_arn = Arn(ca_outputs["TrustAnchorArn"])
        ca_state = CA(
            stack_name=ca_stack,
            mode=CAMode.PCA_EXISTING,
            trust_anchor_arn=trust_anchor_arn,
            pca_arn=Arn(pca_arn),
        )

    new_state.ca = ca_state
    click.echo(f"       Trust Anchor: {trust_anchor_arn}")

    # Save state
    state.save(new_state, region, profile)

    click.echo()
    click.secho("Initialization complete!", fg="green", bold=True)
    click.echo()
    click.echo("Next steps:")
    click.echo("  1. Create a role:  iam-ra role create <role-name> --policies <policy-arns>")
    click.echo("  2. Onboard hosts:  iam-ra onboard <hostname> --role <role-name>")
