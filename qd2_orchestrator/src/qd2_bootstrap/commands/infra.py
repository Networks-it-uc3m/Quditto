import os
import typer
import yaml
from pathlib import Path
from rich import print as rprint

from qd2_bootstrap.models.infra_spec import InfraSpec
from qd2_bootstrap.utils.tf_templates import MAIN_TF
from qd2_bootstrap.utils.terraform import TerraformClient

app = typer.Typer(no_args_is_help=True)

def _ensure_workdir(path: Path):
    path.mkdir(parents=True, exist_ok=True)

def _write_if_missing(path: Path, content: str, force: bool = False):
    if path.exists() and not force:
        return
    path.write_text(content)

def _write_tfvars(path: Path, spec: InfraSpec):
    s = spec.infraSetup
    # We write only NON-secret variables into terraform.tfvars
    tfvars = f"""\
cluster_name = "{s.clusterName}"
count_cp     = {s.countCp}
count_worker = {s.countWorker}
image_name   = "{s.imageName}"
flavor_name  = "{s.flavorName}"
keypair_name = "{s.keypairName}"
network_uuid = "{s.networkUuid}"

# Provider variables (non-secret here)
auth_url     = "{s.openstack.authUrl}"
region       = "{s.openstack.region}"
user_name    = "{s.openstack.userName}"
tenant_id    = "{s.openstack.tenantId}"
domain_name  = "{s.openstack.domainName}"

# password is NOT written here; provided via ENV TF_VAR_password
"""
    path.write_text(tfvars)

def _env_for_openstack(spec: InfraSpec) -> dict:
    """Return env dict with TF_VAR_* and OS_* for Terraform/OpenStack provider."""
    s = spec.infraSetup
    env = {}
    # Pass password via environment (prefer OS_PASSWORD if not given in YAML)
    password = s.openstack.password or os.environ.get("OS_PASSWORD")
    if not password:
        raise ValueError("OpenStack password not provided: set 'infraSetup.openstack.password' in YAML or export OS_PASSWORD")

    # Terraform variable form
    env["TF_VAR_password"] = password

    # Also export OpenStack standard envs (many providers/readers expect them)
    env["OS_AUTH_URL"] = s.openstack.authUrl
    env["OS_USERNAME"] = s.openstack.userName
    env["OS_PASSWORD"] = password
    env["OS_TENANT_ID"] = s.openstack.tenantId
    env["OS_REGION_NAME"] = s.openstack.region
    env["OS_USER_DOMAIN_NAME"] = s.openstack.domainName

    return env

@app.command()
def up(
    file: Path = typer.Option(..., "--file", "-f", exists=True, readable=True, help="Infra spec YAML"),
    force_main: bool = typer.Option(False, "--force-main", help="Overwrite main.tf if already exists"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Run 'terraform plan' instead of 'apply'"),
    auto_approve: bool = typer.Option(True, "--auto-approve/--no-auto-approve", help="Pass -auto-approve to 'apply'"),
):
    """
    Generate Terraform working dir from spec and run init + plan/apply.
    """
    # 1) Load + validate spec
    try:
        data = yaml.safe_load(file.read_text())
        spec = InfraSpec.model_validate(data)
    except Exception as e:
        rprint(f"[bold red]Spec validation error:[/] {e}")
        raise typer.Exit(code=2)

    workdir = Path(spec.infraSetup.workdir).expanduser().resolve()
    _ensure_workdir(workdir)

    # 2) Write main.tf (template) and terraform.tfvars
    main_tf = workdir / "main.tf"
    tfvars = workdir / "terraform.tfvars"
    _write_if_missing(main_tf, MAIN_TF, force=force_main)
    _write_tfvars(tfvars, spec)

    # 3) Terraform client with proper env (secrets via ENV)
    extra_env = _env_for_openstack(spec)
    tf = TerraformClient(workdir=workdir, extra_env=extra_env)

    rprint(f"[bold cyan]Terraform up[/]  workdir: {workdir}")
    rc = tf.init()
    if rc != 0:
        raise typer.Exit(code=rc)

    if dry_run:
        rc = tf.plan()
        if rc != 0:
            raise typer.Exit(code=rc)
        rprint("[green]Plan complete (dry-run).[/]")
        raise typer.Exit(code=0)

    rc = tf.apply(auto_approve=auto_approve)
    if rc != 0:
        raise typer.Exit(code=rc)
    rprint("[green]Apply complete.[/]")

@app.command()
def down(
    file: Path = typer.Option(..., "--file", "-f", exists=True, readable=True, help="Infra spec YAML (to locate workdir and auth)"),
    auto_approve: bool = typer.Option(True, "--auto-approve/--no-auto-approve", help="Pass -auto-approve to 'destroy'"),
):
    """
    Destroy the Terraform-managed infrastructure (in the given workdir).
    """
    # 1) Load + validate to get workdir and creds
    try:
        data = yaml.safe_load(file.read_text())
        spec = InfraSpec.model_validate(data)
    except Exception as e:
        rprint(f"[bold red]Spec validation error:[/] {e}")
        raise typer.Exit(code=2)

    workdir = Path(spec.infraSetup.workdir).expanduser().resolve()
    if not workdir.exists():
        rprint(f"[yellow]Workdir not found: {workdir}[/]")
        raise typer.Exit(code=0)

    extra_env = _env_for_openstack(spec)
    tf = TerraformClient(workdir=workdir, extra_env=extra_env)

    rprint(f"[bold cyan]Terraform down[/]  workdir: {workdir}")
    rc = tf.destroy(auto_approve=auto_approve)
    if rc != 0:
        raise typer.Exit(code=rc)
    rprint("[green]Destroy complete.[/]")
