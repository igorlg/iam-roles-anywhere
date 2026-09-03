# IAM Roles Anywhere CLI - Architecture Design

## Principles

1. **Separation of concerns**: CLI parsing is separate from business logic
2. **Single responsibility**: Each module does one thing well
3. **Composition over conditionals**: Small operations compose into workflows
4. **Testability**: Core logic can be tested without CLI framework
5. **Monadic error handling**: No exceptions in business logic, use `Result[T, E]`
6. **Explicit dependencies**: Pass AWS session, don't rely on implicit globals

---

## Layer Architecture

```text
┌─────────────────────────────────────────────────────────┐
│                    CLI Layer (commands/)                │
│  Parse args, create Session, call workflows, print     │
│  ONLY place that unwraps Results and handles errors    │
└─────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│                 Workflow Layer (workflows/)             │
│  Orchestrate operations, chain Results                 │
└─────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│              Operations Layer (operations/)             │
│  Atomic operations, return Result[T, E]                │
└─────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│                  Infrastructure Layer (lib/)            │
│  AWS clients, file I/O, crypto primitives              │
└─────────────────────────────────────────────────────────┘
```

---

## Result Type (`lib/result.py`)

Monadic error handling - no exceptions in business logic.

```python
from dataclasses import dataclass
from typing import Generic, TypeVar, Callable

T = TypeVar("T")
E = TypeVar("E")
U = TypeVar("U")

@dataclass(frozen=True, slots=True)
class Ok(Generic[T]):
    value: T

@dataclass(frozen=True, slots=True)
class Err(Generic[E]):
    error: E

type Result[T, E] = Ok[T] | Err[E]

# Helper constructors
def ok(value: T) -> Ok[T]:
    return Ok(value)

def err(error: E) -> Err[E]:
    return Err(error)

# Combinators
def map_result(result: Result[T, E], f: Callable[[T], U]) -> Result[U, E]:
    match result:
        case Ok(value):
            return Ok(f(value))
        case Err(error):
            return Err(error)

def flat_map(result: Result[T, E], f: Callable[[T], Result[U, E]]) -> Result[U, E]:
    match result:
        case Ok(value):
            return f(value)
        case Err(error):
            return Err(error)
```

Usage:

```python
def deploy_stack(...) -> Result[StackOutputs, DeployError]:
    ...

# In workflows - chain with match
match deploy_init(session, namespace):
    case Ok(init_result):
        # continue with init_result
    case Err(e):
        return Err(e)

# Or use flat_map for cleaner chaining
result = flat_map(
    deploy_init(session, namespace),
    lambda init: deploy_ca(session, namespace, init.bucket_name)
)
```

---

## AWS Session (`lib/aws.py`)

Single session created at CLI entry, passed to all operations.

```python
from dataclasses import dataclass
from functools import cached_property
import boto3
from mypy_boto3_cloudformation import CloudFormationClient
from mypy_boto3_s3 import S3Client
from mypy_boto3_ssm import SSMClient
from mypy_boto3_secretsmanager import SecretsManagerClient

@dataclass(frozen=True)
class AwsContext:
    """AWS session and clients. Created once at CLI entry."""
    region: str
    profile: str | None
    
    @cached_property
    def session(self) -> boto3.Session:
        return boto3.Session(region_name=self.region, profile_name=self.profile)
    
    @cached_property
    def cfn(self) -> CloudFormationClient:
        return self.session.client("cloudformation")
    
    @cached_property
    def s3(self) -> S3Client:
        return self.session.client("s3")
    
    @cached_property
    def ssm(self) -> SSMClient:
        return self.session.client("ssm")
    
    @cached_property
    def secrets(self) -> SecretsManagerClient:
        return self.session.client("secretsmanager")
    
    @property
    def account_id(self) -> str:
        return self.session.client("sts").get_caller_identity()["Account"]
```

Created once in CLI:

```python
@click.command()
@click.option("--region", "-r", default="ap-southeast-2")
@click.option("--profile", "-p", default=None)
def init(region: str, profile: str | None, ...):
    ctx = AwsContext(region=region, profile=profile)
    result = workflows.init.init(ctx, config)
    ...
```

---

## Error Types (`lib/errors.py`)

Structured error types for each failure mode.

```python
from dataclasses import dataclass

@dataclass(frozen=True)
class NotInitializedError:
    namespace: str
    message: str = "Namespace not initialized"

@dataclass(frozen=True)
class StackDeployError:
    stack_name: str
    status: str
    reason: str

@dataclass(frozen=True)
class RoleNotFoundError:
    namespace: str
    role_name: str

@dataclass(frozen=True)
class RoleInUseError:
    role_name: str
    hosts: list[str]

@dataclass(frozen=True)
class HostNotFoundError:
    namespace: str
    hostname: str

@dataclass(frozen=True)
class CAKeyNotFoundError:
    expected_path: str

@dataclass(frozen=True)
class S3ReadError:
    bucket: str
    key: str
    reason: str

@dataclass(frozen=True)
class AlreadyExistsError:
    resource_type: str  # "role", "host", etc.
    name: str

# Union of all errors for Result types
type InitError = StackDeployError | S3ReadError
type CAError = StackDeployError | CAKeyNotFoundError | S3ReadError
type RoleError = NotInitializedError | StackDeployError | AlreadyExistsError
type HostError = NotInitializedError | RoleNotFoundError | CAKeyNotFoundError | StackDeployError
```

---

## Operations Layer (`operations/`)

Atomic, single-purpose operations. Return `Result[T, E]`. Take `AwsContext` as first argument.

### `operations/infra.py` - Infrastructure stack operations

```python
@dataclass(frozen=True)
class InitResult:
    stack_name: str
    bucket_name: str
    bucket_arn: Arn
    kms_key_arn: Arn

def deploy_init(ctx: AwsContext, namespace: str) -> Result[InitResult, StackDeployError]
def delete_init(ctx: AwsContext, namespace: str) -> Result[None, StackDeployError]
```

### `operations/ca.py` - Certificate Authority operations

```python
@dataclass(frozen=True)
class SelfSignedCAResult:
    stack_name: str
    trust_anchor_arn: Arn
    cert_s3_key: str
    local_key_path: Path

@dataclass(frozen=True)
class PCAResult:
    stack_name: str
    trust_anchor_arn: Arn
    pca_arn: Arn

def create_self_signed_ca(
    ctx: AwsContext,
    namespace: str,
    bucket_name: str,
    validity_years: int = 10,
) -> Result[SelfSignedCAResult, CAError]

def create_pca_ca(
    ctx: AwsContext,
    namespace: str,
    key_algorithm: str = "EC_prime256v1",
    validity_years: int = 10,
) -> Result[PCAResult, StackDeployError]

def attach_existing_pca(
    ctx: AwsContext,
    namespace: str,
    pca_arn: str,
) -> Result[PCAResult, StackDeployError]

def delete_ca(ctx: AwsContext, stack_name: str) -> Result[None, StackDeployError]
```

### `operations/role.py` - Role operations

```python
@dataclass(frozen=True)
class RoleResult:
    stack_name: str
    role_arn: Arn
    profile_arn: Arn
    policies: tuple[Arn, ...]

def create_role(
    ctx: AwsContext,
    namespace: str,
    name: str,
    policies: list[str] = [],
    session_duration: int = 3600,
) -> Result[RoleResult, StackDeployError]

def delete_role(ctx: AwsContext, stack_name: str) -> Result[None, StackDeployError]
```

### `operations/host.py` - Host operations

Teardown only, since v3. A v3 host has no CloudFormation stack and no S3
artifacts, so this exists purely to clean up hosts enrolled under v2.

```python
def offboard_host(
    ctx: AwsContext,
    stack_name: str,
    bucket_name: str,
    namespace: str,
    hostname: str,
) -> Result[None, StackDeployError]
```

### `operations/enrol.py` - CSR signing

Replaces the v2 `onboard_host_*` operations. It signs, and does not deploy: the
key already exists on the host, so there is nothing to provision.

```python
def sign_host_csr(
    ctx: AwsContext,
    csr_pem: str,
    hostname: str,
    ca: CA,
    bucket_name: str,
    validity_days: int = 365,
) -> Result[str, SignHostCsrError]
    """Return a signed certificate PEM.

    Dispatches on CA mode: signs locally for a self-signed CA, or submits the
    CSR to ACM Private CA. Validates the CSR's self-signature and key type
    first, and for the self-signed path rebuilds the subject from `hostname`
    rather than trusting the CSR.
    """
```

### `lib/keystore.py` - where private keys live

Not an AWS operation, but the other half of enrolment. A `KeyStore` generates a
key and CSR, and later pairs a certificate with that key. The protocol exists so
the key never has to be returned to the caller.

```python
class KeyStore(Protocol):
    def generate(label, common_name, *, overwrite=False) -> Result[EnrolmentRequest, ...]
    def install_certificate(label, pem) -> Result[CredentialSource, ...]
    def locate(label) -> Result[CredentialSource, ...]
    def delete(label) -> Result[None, ...]
```

Backends: `FileKeyStore` (all platforms) and `KeychainKeyStore` (macOS,
non-extractable). `CredentialSource` is a tagged union — `FileCredentialSource`
carries paths, `KeychainCredentialSource` carries a selector — matching the
Nix module options, because `aws_signing_helper` treats `--cert-selector` as
mutually exclusive with `--certificate`/`--private-key`.

`operations/secrets.py` was **deleted in v3**. It generated the SOPS file that
carried a host's private key; there is no longer a private key to carry.

---

## Workflow Layer (`workflows/`)

Orchestrate operations into complete user intents. Chain Results. Take `AwsContext` as first argument.

### `workflows/init.py`

```python
@dataclass(frozen=True)
class InitConfig:
    namespace: str
    ca_mode: CAMode
    pca_arn: str | None = None  # Only for PCA_EXISTING
    ca_validity_years: int = 10

type InitWorkflowError = InitError | CAError

def init(ctx: AwsContext, config: InitConfig) -> Result[State, InitWorkflowError]:
    """
    1. Deploy init stack
    2. Deploy CA stack (based on mode)
    3. Save and return state
    """
```

### `workflows/destroy.py`

```python
type DestroyError = StackDeployError | NotInitializedError

def destroy(
    ctx: AwsContext,
    namespace: str,
    force: bool = False,
) -> Result[None, DestroyError]:
    """
    1. Load state
    2. Delete all host stacks
    3. Delete all role stacks  
    4. Delete CA stack
    5. Delete init stack
    6. Clear state
    """
```

### `workflows/role.py`

```python
type CreateRoleError = NotInitializedError | AlreadyExistsError | StackDeployError
type DeleteRoleError = NotInitializedError | RoleNotFoundError | RoleInUseError | StackDeployError

def create_role(
    ctx: AwsContext,
    namespace: str,
    name: str,
    policies: list[str],
    session_duration: int,
) -> Result[Role, CreateRoleError]:
    """
    1. Load state, validate initialized
    2. Check role doesn't exist
    3. Deploy role stack
    4. Update state
    """

def delete_role(
    ctx: AwsContext,
    namespace: str,
    name: str,
    force: bool = False,
) -> Result[None, DeleteRoleError]:
    """
    1. Load state
    2. Check no hosts using role (unless force)
    3. Delete role stack
    4. Update state
    """

def list_roles(
    ctx: AwsContext,
    namespace: str,
) -> Result[dict[str, Role], NotInitializedError]:
    """Load state, return roles dict."""
```

### `workflows/host.py`

```python
type OffboardError = NotInitializedError | HostNotFoundError | StackDeployError

def offboard(
    ctx: AwsContext,
    namespace: str,
    hostname: str,
) -> Result[None, OffboardError]:
    """
    1. Load state
    2. Delete host stack
    3. Cleanup S3
    4. Update state
    """

def list_hosts(
    ctx: AwsContext,
    namespace: str,
) -> Result[dict[str, Host], NotInitializedError]:
    """Load state, return hosts dict."""
```

`add_role` / `remove_role` also live here. Since v3 they update the recorded role
list only and no longer rewrite a SOPS file — a certificate carries no role
information, so granting a role is a change to the IAM trust policy and the
host's Nix profiles, not to its certificate.

### `workflows/enrol.py`

The v3 replacement for `host onboard`. Four verbs rather than flags on one
command, because their preconditions genuinely differ — and note which ones take
an `AwsContext`. The host-side verbs do not, so the *signature itself* guarantees
a host needs no AWS credentials. Tests assert this, so a refactor cannot quietly
reintroduce the dependency.

```python
type RequestError = KeyStoreError
type InstallError = KeyStoreError | CsrParseError
type ApproveError = (
    NotInitializedError | AccountMismatchError | RoleNotFoundError
    | CAScopeNotFoundError | HostAlreadyExistsError | SignHostCsrError
    | StateLoadError | StateSaveError
)
type EnrolError = ApproveError | KeyStoreError

# --- on the host, no AWS ---

def request_certificate(config: RequestConfig) -> Result[RequestResult, RequestError]:
    """Generate a key in the host's key store, return a CSR for it.

    Note the absent `ctx`. Returns no private key, by design.
    """

def install_certificate(config: InstallConfig) -> Result[InstallResult, InstallError]:
    """Pair a signed certificate with the key already in the store.

    Refuses a certificate whose public key does not match the stored key, which
    catches both a certificate meant for another host and one superseded by a
    later `request`.
    """

# --- where the CA lives ---

def approve_certificate(
    ctx: AwsContext, config: ApproveConfig
) -> Result[ApproveResult, ApproveError]:
    """Validate and sign a CSR, then record the host in state.

    1. Load state, validate initialized, check account matches namespace
    2. Resolve roles -> scope -> CA
    3. Sign via operations.sign_host_csr (validates the CSR first)
    4. Record the host: key_store, certificate_serial, not_after
    """

# --- both halves, one process ---

def enrol_host(ctx: AwsContext, config: EnrolConfig) -> Result[EnrolResult, EnrolError]:
    """request -> approve -> install, for a host that has AWS access."""
```

`enrol_host` calls the other three rather than reimplementing them, which keeps
the split and combined flows on one code path.

### `workflows/status.py`

```python
@dataclass(frozen=True)
class Status:
    namespace: str
    region: str
    initialized: bool
    init: Init | None
    ca: CA | None
    roles: dict[str, Role]
    hosts: dict[str, Host]

def get_status(ctx: AwsContext, namespace: str) -> Status:
    """Load state and return status. Never fails - returns empty status if not initialized."""
```

---

## CLI Layer (`commands/`)

Thin wrappers. Parse arguments, create `AwsContext`, call workflows, unwrap Results, format output.

### `commands/init.py`

```python
@click.command()
@click.option("--namespace", "-n", default="default")
@click.option("--region", "-r", default="ap-southeast-2")
@click.option("--profile", "-p", default=None)
@click.option("--ca-mode", type=click.Choice([...]), default="self-signed")
@click.option("--pca-arn", default=None)
@click.option("--ca-validity-years", default=10)
def init(namespace, region, profile, ca_mode, pca_arn, ca_validity_years):
    ctx = AwsContext(region=region, profile=profile)
    config = InitConfig(namespace=namespace, ca_mode=CAMode(ca_mode), ...)
    
    match workflows.init.init(ctx, config):
        case Ok(state):
            click.secho("Initialized successfully!", fg="green")
            # Print state summary
        case Err(e):
            _print_error(e)
            raise SystemExit(1)
```

### `commands/destroy.py`

```python
@click.command()
@click.option("--namespace", "-n", default="default")
@click.option("--region", "-r", default="ap-southeast-2")  
@click.option("--profile", "-p", default=None)
@click.option("--force", is_flag=True)
@click.confirmation_option(prompt="This will delete all resources. Continue?")
def destroy(namespace, region, profile, force):
    ctx = AwsContext(region=region, profile=profile)
    
    match workflows.destroy.destroy(ctx, namespace, force):
        case Ok(_):
            click.secho("Destroyed successfully!", fg="green")
        case Err(e):
            _print_error(e)
            raise SystemExit(1)
```

### `commands/role.py`

```python
@click.group()
def role():
    """Manage IAM roles."""

@role.command("create")
@click.argument("name")
@click.option("--namespace", "-n", default="default")
@click.option("--region", "-r", default="ap-southeast-2")
@click.option("--profile", "-p", default=None)
@click.option("--policies", multiple=True)
@click.option("--session-duration", default=3600)
def create(name, namespace, region, profile, policies, session_duration):
    ctx = AwsContext(region=region, profile=profile)
    
    match workflows.role.create_role(ctx, namespace, name, list(policies), session_duration):
        case Ok(role):
            click.secho(f"Role '{name}' created!", fg="green")
            click.echo(f"  ARN: {role.role_arn}")
        case Err(e):
            _print_error(e)
            raise SystemExit(1)

@role.command("delete")
@click.argument("name")
@click.option("--force", is_flag=True)
# ... common options ...
def delete(name, namespace, region, profile, force):
    ctx = AwsContext(region=region, profile=profile)
    
    match workflows.role.delete_role(ctx, namespace, name, force):
        case Ok(_):
            click.secho(f"Role '{name}' deleted!", fg="green")
        case Err(e):
            _print_error(e)
            raise SystemExit(1)

@role.command("list")
# ... common options ...
def list_cmd(namespace, region, profile):
    ctx = AwsContext(region=region, profile=profile)
    
    match workflows.role.list_roles(ctx, namespace):
        case Ok(roles):
            _print_roles_table(roles)
        case Err(e):
            _print_error(e)
            raise SystemExit(1)
```

### `commands/host.py`

```python
@click.group()
def host():
    """Manage hosts."""

# Host-side. Note there is no AwsContext to build - `request` cannot make an
# AWS call even by accident.
@host.command("request")
@click.argument("hostname")
@click.option("--namespace", "-n", default="default")
@click.option("--scope", "-s", default="default")
@click.option("--key-store", type=click.Choice(["files", "macosKeychain"]), default="files")
@click.option("--out", type=click.Path())
@click.option("--overwrite", is_flag=True)
def request(hostname, namespace, scope, key_store, out, overwrite):
    result = handle_result(request_certificate(RequestConfig(
        namespace=namespace, hostname=hostname, scope=scope,
        key_store=key_store, overwrite=overwrite,
    )))
    # CSR to stdout, human output to stderr, so the flow pipes.
    _write_or_echo(result.csr_pem, out, label="CSR")

# Host-side, and likewise context-free.
@host.command("install")
@click.argument("hostname")
@click.option("--certificate", "-c", required=True)
# ... namespace / scope / key-store, which must match `request` ...
def install(hostname, certificate, namespace, scope, key_store):
    result = handle_result(install_certificate(InstallConfig(
        namespace=namespace, certificate_pem=_read_pem(certificate),
        scope=scope, key_store=key_store,
    )))
    for line in _render_certificate_stanza(result.credential_source):
        click.echo(line, err=True)

# CA-side. This one needs credentials.
@host.command("approve")
@click.argument("hostname")
@click.option("--role", "-R", required=True, multiple=True)
@click.option("--csr", required=True)      # path, or '-' for stdin
@click.option("--validity-days", default=365)
@click.option("--out", type=click.Path())
@click.option("--overwrite", is_flag=True)
# ... common AWS options ...
def approve(hostname, role, csr, validity_days, out, overwrite, namespace, region, profile):
    ctx = make_context(region=region, profile=profile)
    result = handle_result(approve_certificate(ctx, ApproveConfig(
        namespace=namespace, hostname=hostname, role_names=_split_roles(role),
        csr_pem=_read_pem(csr), validity_days=validity_days, overwrite=overwrite,
    )))
    _write_or_echo(result.certificate_pem, out, label="Certificate")
    _print_nix_snippet(result)

# Both halves, for a host that has AWS access.
@host.command("enroll")
# ... same options as approve, plus --key-store ...
def enroll(...):
    ctx = make_context(region=region, profile=profile)
    result = handle_result(enrol_host(ctx, EnrolConfig(...)))
    _print_nix_snippet(result)

@host.command("offboard")
@click.argument("hostname")
# ... common options ...
def offboard(hostname, namespace, region, profile):
    ctx = AwsContext(region=region, profile=profile)
    
    match workflows.host.offboard(ctx, namespace, hostname):
        case Ok(_):
            click.secho(f"Host '{hostname}' offboarded!", fg="green")
        case Err(e):
            _print_error(e)
            raise SystemExit(1)

@host.command("list")
# ... common options ...
def list_cmd(namespace, region, profile):
    ctx = AwsContext(region=region, profile=profile)
    
    match workflows.host.list_hosts(ctx, namespace):
        case Ok(hosts):
            _print_hosts_table(hosts)
        case Err(e):
            _print_error(e)
            raise SystemExit(1)
```

### `commands/status.py`

```python
@click.command()
@click.option("--namespace", "-n", default="default")
@click.option("--region", "-r", default="ap-southeast-2")
@click.option("--profile", "-p", default=None)
def status(namespace, region, profile):
    ctx = AwsContext(region=region, profile=profile)
    status = workflows.status.get_status(ctx, namespace)
    _print_status(status)
```

### `commands/_error.py` - Error formatting helpers

```python
def _print_error(error) -> None:
    """Format and print error based on type."""
    match error:
        case NotInitializedError(namespace):
            click.secho(f"Error: Namespace '{namespace}' not initialized.", fg="red")
            click.echo("Run 'iam-ra init' first.")
        case RoleNotFoundError(_, role_name):
            click.secho(f"Error: Role '{role_name}' not found.", fg="red")
        case RoleInUseError(role_name, hosts):
            click.secho(f"Error: Role '{role_name}' is in use by hosts:", fg="red")
            for h in hosts:
                click.echo(f"  - {h}")
            click.echo("Use --force to delete anyway.")
        case StackDeployError(stack_name, status, reason):
            click.secho(f"Error: Stack '{stack_name}' deployment failed.", fg="red")
            click.echo(f"  Status: {status}")
            click.echo(f"  Reason: {reason}")
        case _:
            click.secho(f"Error: {error}", fg="red")
```

---

## File Structure

```text
iam_ra_cli/
├── __init__.py
├── main.py                    # CLI entry point, registers commands
├── models/
│   └── __init__.py            # Arn, CAMode, State, Init, CA, Role, Host
├── lib/
│   ├── aws.py                 # AwsContext (session + clients)
│   ├── result.py              # Result[T, E], Ok, Err
│   ├── errors.py              # Error types
│   ├── cfn.py                 # CloudFormation helpers
│   ├── crypto.py              # CSR + certificate signing
│   ├── keystore.py            # files + macosKeychain key stores
│   ├── paths.py               # XDG paths
│   ├── state.py               # State load/save
│   ├── templates.py           # Template loading
│   └── storage/
│       ├── file.py            # Local file I/O
│       └── s3.py              # S3 I/O
├── operations/
│   ├── __init__.py
│   ├── infra.py               # Init stack operations
│   ├── ca.py                  # CA stack operations
│   ├── role.py                # Role stack operations
│   ├── host.py                # Host stack operations
│   └── enrol.py               # CSR signing (self-signed or PCA)
├── workflows/
│   ├── __init__.py
│   ├── init.py                # Init workflow
│   ├── destroy.py             # Destroy workflow
│   ├── role.py                # Role workflows
│   ├── host.py                # Host lifecycle (offboard, list, add/remove-role)
│   ├── enrol.py               # request / install / approve / enrol
│   └── status.py              # Status workflow
├── commands/
│   ├── __init__.py
│   ├── _error.py              # Error formatting helpers
│   ├── init.py                # iam-ra init
│   ├── destroy.py             # iam-ra destroy
│   ├── role.py                # iam-ra role {create,delete,list}
│   ├── host.py                # iam-ra host {request,approve,install,enroll,...}
│   └── status.py              # iam-ra status
└── data/
    └── cloudformation/
        ├── init.yaml
        ├── rootca-self-signed.yaml
        ├── rootca-pca-new.yaml
        ├── rootca-pca-existing.yaml
        └── role.yaml
```

No `host.yaml`: v3 hosts have no CloudFormation stack.

---

## CLI Command Structure

```text
iam-ra
├── init                       # Initialize infrastructure + CA
├── destroy                    # Tear down everything
├── status                     # Show current state
├── role
│   ├── create <name>          # Create role
│   ├── delete <name>          # Delete role
│   └── list                   # List roles
└── host
    ├── request <hostname>     # On the host: generate key, emit CSR (no AWS)
    ├── approve <hostname>     # At the CA: sign the CSR, record the host
    ├── install <hostname>     # On the host: pair the certificate (no AWS)
    ├── enroll <hostname>      # All three, for a host with AWS access
    ├── add-role <host> <role>    # Record an extra role
    ├── remove-role <host> <role> # Record a removed role
    ├── offboard <hostname>    # Offboard host
    └── list                   # List hosts
```

---

## Error Handling

- **Operations/Workflows**: Return `Result[T, E]` - never raise exceptions
- **CLI layer**: Pattern match on Results, format errors nicely, exit with code 1 on Err
- **Lib layer**: May raise exceptions (e.g., boto3 errors) - operations catch and wrap in Err

```python
# In operations - catch low-level errors, return Result
def deploy_init(ctx: AwsContext, namespace: str) -> Result[InitResult, StackDeployError]:
    try:
        outputs = cfn.deploy(ctx.cfn, ...)
        return Ok(InitResult(...))
    except ClientError as e:
        return Err(StackDeployError(stack_name, "FAILED", str(e)))

# In workflows - chain Results
def init(ctx: AwsContext, config: InitConfig) -> Result[State, InitWorkflowError]:
    match deploy_init(ctx, config.namespace):
        case Err(e):
            return Err(e)
        case Ok(init_result):
            match create_self_signed_ca(ctx, ...):
                case Err(e):
                    return Err(e)
                case Ok(ca_result):
                    return Ok(State(...))

# In CLI - unwrap and handle
match workflows.init.init(ctx, config):
    case Ok(state):
        click.echo("Success!")
    case Err(e):
        _print_error(e)
        raise SystemExit(1)
```

---

## Open Questions

1. **Refresh command?** - Rebuild state from actual CloudFormation stacks if out of sync
2. ~~**Rotate command?**~~ - Resolved. v3 rotation is
   `iam-ra host enroll --overwrite` (or `request` + `approve` + `install`), run on
   the host. The v2 `rotate-cert` was removed rather than ported: it rotated the
   key from the admin workstation, which is impossible once the key never leaves
   the host.
3. **Export command?** - Export credentials in different formats (JSON, env vars, etc.)
4. **CRL generation and import?** - IAM Roles Anywhere supports revocation via
   `ImportCrl`, but this tool neither generates nor imports a CRL, so offboarding
   does not invalidate a certificate. See [SECURITY.md](../SECURITY.md).
