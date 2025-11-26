from pathlib import Path
from typing import Dict
from rich import print as rprint
from qd2_bootstrap.models.infra_spec import InfraSpec
from qd2_bootstrap.utils.tf_templates import MAIN_TF

def ensure_workdir(path: Path):
    path.mkdir(parents=True, exist_ok=True)

def write_if_missing(path: Path, content: str, force: bool = False):
    if path.exists() and not force:
        return
    path.write_text(content)

def write_tfvars(path: Path, spec: InfraSpec):
    s = spec.infraSetup
    tfvars = f"""\
cluster_name = "{s.clusterName}"
count_cp     = {s.countCp}
count_worker = {s.countWorker}
image_name   = "{s.imageName}"
flavor_name  = "{s.flavorName}"
keypair_name = "{s.keypairName}"
network_uuid = "{s.networkUuid}"

auth_url     = "{s.openstack.authUrl}"
region       = "{s.openstack.region}"
user_name    = "{s.openstack.userName}"
tenant_id    = "{s.openstack.tenantId}"
domain_name  = "{s.openstack.domainName}"
# password via ENV: TF_VAR_password
"""
    path.write_text(tfvars)

def env_for_openstack(spec: InfraSpec) -> Dict[str, str]:
    import os
    s = spec.infraSetup
    password = s.openstack.password or os.environ.get("OS_PASSWORD")
    if not password:
        raise ValueError("OpenStack password not provided (set infraSetup.openstack.password or OS_PASSWORD).")
    env = {}
    env["TF_VAR_password"] = password
    env["OS_AUTH_URL"] = s.openstack.authUrl
    env["OS_USERNAME"] = s.openstack.userName
    env["OS_PASSWORD"] = password
    env["OS_TENANT_ID"] = s.openstack.tenantId
    env["OS_REGION_NAME"] = s.openstack.region
    env["OS_USER_DOMAIN_NAME"] = s.openstack.domainName
    return env

def prepare_tf_workdir(spec: InfraSpec, force_main: bool = False) -> Path:
    """Create workdir and write main.tf + terraform.tfvars; return workdir."""
    workdir = Path(spec.infraSetup.workdir).expanduser().resolve()
    ensure_workdir(workdir)
    write_if_missing(workdir / "main.tf", MAIN_TF, force=force_main)
    write_tfvars(workdir / "terraform.tfvars", spec)
    rprint(f"[cyan]Terraform workdir:[/] {workdir}")
    return workdir
