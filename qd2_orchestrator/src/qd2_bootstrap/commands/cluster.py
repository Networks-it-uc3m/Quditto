import os
import shutil
import tempfile
from pathlib import Path
from typing import List, Tuple

import typer
import yaml
from rich import print as rprint

from qd2_bootstrap.models.cluster_spec import ClusterSpec
from qd2_bootstrap.utils.kubeone_templates import render_manifest
from qd2_bootstrap.utils.kubeone import KubeOneClient
from qd2_bootstrap.utils.terraform import TerraformClient
from qd2_bootstrap.utils.kubectl import Kubectl
from qd2_bootstrap.utils.wait_ssh import wait_ssh_all
from qd2_bootstrap.utils.infra_writer import (
    prepare_tf_workdir,
    env_for_openstack,
)

app = typer.Typer(no_args_is_help=True)

# --------------------------
# Helpers (files & manifest)
# --------------------------

def _manifest_tmp(content: str) -> Path:
    """Write a temporary KubeOne manifest and return its path."""
    fd, path = tempfile.mkstemp(prefix="k1-", suffix=".yaml")
    p = Path(path)
    with os.fdopen(fd, "w") as f:
        f.write(content)
    return p

def _expected_kubeone_kubeconfig(cluster_name: str, base_dir: Path) -> Path:
    """KubeOne drops '<cluster_name>-kubeconfig' in the current working directory."""
    return base_dir / f"{cluster_name}-kubeconfig"

def _save_kubeconfig(cluster_name: str, src_dir: Path, outdir: Path) -> Path:
    """Copy kubeone-produced kubeconfig to a stable path ./clusters/<name>/kubeconfig."""
    src = _expected_kubeone_kubeconfig(cluster_name, src_dir)
    if not src.exists():
        raise FileNotFoundError(f"KubeOne kubeconfig not found: {src}")
    outdir.mkdir(parents=True, exist_ok=True)
    dst = outdir / "kubeconfig"
    shutil.copyfile(src, dst)
    return dst

def _helm_releases(spec: ClusterSpec) -> List[dict]:
    """Normalize helmReleases to dicts used by the template renderer."""
    hr = []
    for r in spec.clusterSetup.helmReleases:
        hr.append({
            "chart": r.chart,
            "repoURL": r.repoURL,
            "namespace": r.namespace,
            "version": r.version,
            "values": r.values,
        })
    return hr

def _derive_hosts_from_infra(workdir: Path) -> Tuple[List[str], List[str]]:
    """Read Terraform outputs (control_plane_ip, worker_ips) to build host lists."""
    tf = TerraformClient(workdir=workdir)
    outputs = tf.output_json()
    cp = outputs.get("control_plane_ip", {}).get("value")
    workers = outputs.get("worker_ips", {}).get("value", [])
    if not cp or not isinstance(workers, list):
        raise RuntimeError("Terraform outputs missing 'control_plane_ip' or 'worker_ips'")
    return [cp], workers


# ----------
# cluster up
# ----------

@app.command()
def up(
    file: Path = typer.Option(..., "--file", "-f", exists=True, readable=True, help="Cluster spec YAML"),
    use_infra_tfstate: bool = typer.Option(False, "--use-infra-tfstate", help="Pass -t <tfstate> to kubeone"),
    auto_approve: bool = typer.Option(True, "--auto-approve/--no-auto-approve", help="Auto-approve KubeOne apply (-y)"),
    kubeconfig_outdir: Path = typer.Option(None, "--kubeconfig-outdir", help="Where to store kubeconfig (default: ./clusters/<name>)"),
    provision_infra: Path = typer.Option(None, "--provision-infra", help="Infra spec YAML to provision VMs before KubeOne"),
    wait_ssh: bool = typer.Option(True, "--wait-ssh/--no-wait-ssh", help="Wait for SSH on all nodes before applying KubeOne"),
    ssh_timeout: int = typer.Option(300, "--ssh-timeout", help="Max seconds to wait for SSH readiness"),
    post_status: bool = typer.Option(True, "--post-status/--no-post-status", help="Show nodes and kube-system pods after apply"),

):
    """
    Apply the cluster with KubeOne.
    If --provision-infra is provided, create VMs first (Terraform) and then continue.
    """
    try:
        data = yaml.safe_load(file.read_text())
        spec = ClusterSpec.model_validate(data)
    except Exception as e:
        rprint(f"[bold red]Spec validation error:[/] {e}")
        raise typer.Exit(code=2)

    s = spec.clusterSetup
    cwd = Path.cwd()
    tfstate_path = None

    # (Optional) Provision infra now
    if provision_infra:
        rprint("[bold cyan]Provisioning infra (Terraform)...[/]")
        try:
            infra_data = yaml.safe_load(provision_infra.read_text())
            from qd2_bootstrap.models.infra_spec import InfraSpec
            infra_spec = InfraSpec.model_validate(infra_data)
        except Exception as e:
            rprint(f"[bold red]Infra spec validation error:[/] {e}")
            raise typer.Exit(code=2)

        workdir = prepare_tf_workdir(infra_spec, force_main=False)
        extra_env = env_for_openstack(infra_spec)
        tf = TerraformClient(workdir=workdir, extra_env=extra_env)
        rc = tf.init()
        if rc != 0:
            raise typer.Exit(code=rc)
        rc = tf.apply(auto_approve=True)
        if rc != 0:
            raise typer.Exit(code=rc)
        rprint("[green]Infra apply complete.[/]")
        # Force fromInfra mode using this workdir
        s.fromInfra = type("Tmp", (), {"workdir": str(workdir)})()
        tfstate_path = workdir / "terraform.tfstate"

    # Determine hosts
    if s.fromInfra:
        workdir = Path(s.fromInfra.workdir).expanduser().resolve()
        cp_addrs, worker_addrs = _derive_hosts_from_infra(workdir)
        tfstate_path = tfstate_path or (workdir / "terraform.tfstate")
    else:
        cp_addrs = [h.privateAddress for h in s.existingHosts.controlPlane]  # type: ignore
        worker_addrs = [h.privateAddress for h in s.existingHosts.workers]   # type: ignore

    # (Optional) wait SSH on all nodes
    if wait_ssh:
        all_hosts = cp_addrs + worker_addrs
        key = Path(s.ssh.privateKeyFile).expanduser()
        ok = wait_ssh_all(all_hosts, s.ssh.user, key, timeout_total_s=ssh_timeout, every_s=5)
        if not ok:
            raise typer.Exit(code=3)

    # Render manifest
    api_host = s.apiEndpoint.host or cp_addrs[0]
    manifest = render_manifest(
        name=s.name,
        k8s_version=s.kubernetesVersion,
        ssh_user=s.ssh.user,
        ssh_key=s.ssh.privateKeyFile,
        cp_addrs=cp_addrs,
        worker_addrs=worker_addrs,
        api_host=api_host,
        api_port=s.apiEndpoint.port,
        pod_subnet=s.networking.podSubnet,
        svc_subnet=s.networking.serviceSubnet,
        external_cni=bool(s.cni.get("external", False)),
        helm_releases=_helm_releases(spec),
    )
    man_path = _manifest_tmp(manifest)
    rprint(f"[cyan]KubeOne manifest:[/] {man_path}")

    # KubeOne apply
    k1 = KubeOneClient()
    rc = k1.apply(
        manifest_path=man_path,
        tfstate_path=(tfstate_path if (tfstate_path and use_infra_tfstate) else None),
        auto_approve=auto_approve,
    )
    if rc != 0:
        raise typer.Exit(code=rc)
    rprint("[green]KubeOne apply complete.[/]")

    # Save kubeconfig
    outdir = kubeconfig_outdir or (Path("./clusters") / s.name)
    saved_kc = None  # <-- inicializamos aquí

    try:
        saved_kc = _save_kubeconfig(cluster_name=s.name, src_dir=cwd, outdir=outdir)
        rprint(f"[green]Kubeconfig saved:[/] {saved_kc}")
        rprint(f"  export KUBECONFIG={saved_kc}")
    except FileNotFoundError as e:
        rprint(f"[yellow]Warning:[/] {e}")
        # Fallback: intenta usar el kubeconfig que KubeOne dejó en CWD
        kc_cwd = _expected_kubeone_kubeconfig(s.name, cwd)
        if kc_cwd.exists():
            saved_kc = kc_cwd
            rprint(f"[yellow]Using kubeconfig from current directory:[/] {kc_cwd}")
        else:
            rprint("[red]No kubeconfig found after KubeOne apply.[/]")

    # Post status (nodes + kube-system pods)
    if post_status and saved_kc:
        try:
            from qd2_bootstrap.utils.kubectl import Kubectl
            rprint("\n[bold cyan]Cluster status after apply[/]")
            kube = Kubectl(kubeconfig=saved_kc)
            kube.get_nodes()
            kube.get_core_health()
        except Exception as e:
            rprint(f"[yellow]Could not fetch post-apply status:[/] {e}")


# -------------
# cluster down
# -------------

@app.command()
def down(
    file: Path = typer.Option(..., "--file", "-f", exists=True, readable=True, help="Cluster spec YAML"),
    auto_approve: bool = typer.Option(True, "--auto-approve/--no-auto-approve", help="Pass -y to kubeone reset"),
    destroy_infra: bool = typer.Option(False, "--destroy-infra", help="Also destroy Terraform infra if defined (fromInfra or provisioned)"),
):
    """
    Teardown (reset) a Kubernetes cluster created with kubeone.

    - Runs `kubeone reset` to uninstall Kubernetes from the nodes.
    - Optionally (`--destroy-infra`) runs `terraform destroy` for its underlying infra.
    """
    try:
        data = yaml.safe_load(file.read_text())
        spec = ClusterSpec.model_validate(data)
    except Exception as e:
        rprint(f"[bold red]Spec validation error:[/] {e}")
        raise typer.Exit(code=2)

    s = spec.clusterSetup

    # Determine hosts
    tf_workdir = None
    if s.fromInfra:
        tf_workdir = Path(s.fromInfra.workdir).expanduser().resolve()
        cp_addrs, worker_addrs = _derive_hosts_from_infra(tf_workdir)
    else:
        cp_addrs = [h.privateAddress for h in s.existingHosts.controlPlane]  # type: ignore
        worker_addrs = [h.privateAddress for h in s.existingHosts.workers]   # type: ignore

    # Render manifest (same hosts/ssh/apiEndpoint/etc.)
    api_host = s.apiEndpoint.host or cp_addrs[0]
    manifest = render_manifest(
        name=s.name,
        k8s_version=s.kubernetesVersion,
        ssh_user=s.ssh.user,
        ssh_key=s.ssh.privateKeyFile,
        cp_addrs=cp_addrs,
        worker_addrs=worker_addrs,
        api_host=api_host,
        api_port=s.apiEndpoint.port,
        pod_subnet=s.networking.podSubnet,
        svc_subnet=s.networking.serviceSubnet,
        external_cni=bool(s.cni.get("external", False)),
        helm_releases=_helm_releases(spec),
    )
    man_path = _manifest_tmp(manifest)

    # Reset cluster
    k1 = KubeOneClient()
    rc = k1.reset(manifest_path=man_path, auto_approve=auto_approve)
    if rc != 0:
        raise typer.Exit(code=rc)
    rprint("[green]Cluster successfully reset (Kubernetes uninstalled).[/]")

    # Optionally destroy infra
    if destroy_infra and tf_workdir:
        rprint("[yellow]Destroying Terraform infrastructure...[/]")
        tf = TerraformClient(workdir=tf_workdir)
        rc = tf.destroy(auto_approve=auto_approve)
        if rc != 0:
            raise typer.Exit(code=rc)
        rprint("[green]Terraform infra destroyed.[/]")


# ---------------
# cluster status
# ---------------

@app.command()
def status(
    kubeconfig: Path = typer.Option(None, "--kubeconfig", help="Path to kubeconfig (default: ./clusters/<name>/kubeconfig inferred from spec)"),
    file: Path = typer.Option(None, "--file", "-f", exists=True, readable=True, help="Cluster spec YAML (to infer name if kubeconfig not given)"),
    show_system: bool = typer.Option(True, "--show-system/--no-show-system", help="Also list kube-system pods"),
):
    """
    Show cluster status using kubectl (nodes and optionally kube-system pods).
    """
    # Infer kubeconfig if not provided
    kc = kubeconfig
    if kc is None:
        if not file:
            rprint("[red]Either --kubeconfig or --file must be provided to infer kubeconfig path.[/]")
            raise typer.Exit(code=2)
        try:
            data = yaml.safe_load(file.read_text())
            spec = ClusterSpec.model_validate(data)
        except Exception as e:
            rprint(f"[bold red]Spec validation error:[/] {e}")
            raise typer.Exit(code=2)
        name = spec.clusterSetup.name
        kc = Path("./clusters") / name / "kubeconfig"

    if not kc.exists():
        rprint(f"[red]kubeconfig not found at: {kc}[/]")
        raise typer.Exit(code=2)

    kube = Kubectl(kubeconfig=kc)
    rprint(f"[cyan]Using kubeconfig:[/] {kc}")
    if kube.get_nodes() != 0:
        raise typer.Exit(code=1)
    if show_system:
        kube.get_core_health()
