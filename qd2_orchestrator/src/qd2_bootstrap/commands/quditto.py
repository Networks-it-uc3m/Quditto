# qd2_bootstrap/commands/quditto.py
from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional, Tuple
from collections import defaultdict

import typer
import yaml
from rich import print as rprint
from rich.table import Table
from rich import box

# Models & utils
from qd2_bootstrap.models.quditto_deploy_spec import (
    QudittoDeploySpec,
    ComponentRef,
    QNodeRef,
)

from qd2_bootstrap.utils.helm import HelmClient
from qd2_bootstrap.utils.mapping import map_component_values

from qd2_bootstrap.utils.helm_set import dict_to_set_list  
from qd2_bootstrap.utils.kubectl import Kubectl


app = typer.Typer(no_args_is_help=True)


# -----------------------------------------------------------------------------
# Helpers: grouping and planning
# -----------------------------------------------------------------------------
def _target_key(cluster_name: str, kubeconfig: Path) -> Tuple[str, Path]:
    """Key used to aggregate work per target cluster."""
    return (cluster_name, kubeconfig)


def _collect_components(
    spec: QudittoDeploySpec,
    multi_cluster: bool,
    kubeconfig: Optional[Path],
) -> Dict[Tuple[str, Path], List[Tuple[str, ComponentRef]]]:
    """Build a mapping: (cluster_name, kubeconfig) -> [(release_name, component), ...].

    - In multi-cluster mode, resolve `targetCluster` (or `defaultCluster`) from the spec.
    - In single-cluster mode, require `--kubeconfig`.
    """
    per_cluster: Dict[Tuple[str, Path], List[Tuple[str, ComponentRef]]] = defaultdict(list)

    def _add(release_name: str, comp: ComponentRef) -> None:
        if multi_cluster:
            # Resolve logical cluster name and its kubeconfig from the spec
            target_cluster = spec.resolve_target_cluster(comp)
            kc = spec.kubeconfig_for(target_cluster)
            per_cluster[_target_key(target_cluster, kc)].append((release_name, comp))
        else:
            # Single cluster: require CLI --kubeconfig
            if not kubeconfig:
                raise typer.BadParameter("--kubeconfig is required in single-cluster mode")
            per_cluster[_target_key("__single__", kubeconfig)].append((release_name, comp))

    # Controller (optional in your latest spec, deploy only if present)
    if spec.qudittoSetup.qcontroller:
        _add("qcontroller", spec.qudittoSetup.qcontroller)  # type: ignore

    # Orchestrator (optional)
    if spec.qudittoSetup.qorchestrator:
        _add("qorchestrator", spec.qudittoSetup.qorchestrator)  # type: ignore

    # QNodes
    for qn in spec.qudittoSetup.qnodes:
        _add(qn.name, qn)

    return per_cluster


def _print_plan(
    ns: str,
    repo_url: str,
    grouped: Dict[Tuple[str, Path], List[Tuple[str, ComponentRef]]],
) -> None:
    """Pretty-print a deployment plan table per cluster."""
    for (cluster_name, kc_path), items in grouped.items():
        table = Table(
            title=f"Quditto deploy plan → cluster: {cluster_name}  (kubeconfig: {kc_path})",
            box=box.SIMPLE,
            show_header=True,
            header_style="bold",
        )
        table.add_column("Release")
        table.add_column("Chart")
        table.add_column("Version")
        table.add_column("Namespace")
        table.add_column("Node (nodeName)")
        for release, comp in items:
            chart_ref = comp.chart if comp.chart.startswith("quditto/") else f"quditto/{comp.chart}"
            table.add_row(release, chart_ref, comp.version or "-", ns, comp.nodek8s)
        rprint(table)
        rprint(f"[dim]Using repo:[/] {repo_url}\n")


# -----------------------------------------------------------------------------
# quditto deploy
# -----------------------------------------------------------------------------
@app.command()
def deploy(
    file: Path = typer.Option(..., "-f", "--file", exists=True, readable=True, help="Quditto multi/single cluster spec YAML"),
    kubeconfig: Optional[Path] = typer.Option(None, "--kubeconfig", help="(single-cluster) kubeconfig path"),
    namespace: Optional[str] = typer.Option(None, "--namespace", help="Override namespace (spec.namespace default)"),
    dry_run: bool = typer.Option(False, "--dry-run/--no-dry-run", help="Helm dry-run"),
    show_values: bool = typer.Option(False, "--show-values/--no-show-values", help="Print final --set values for each release"),
    multi_cluster: bool = typer.Option(False, "--multi-cluster/--no-multi-cluster", help="Enable multi-cluster mode"),
    plan_only: bool = typer.Option(False, "--plan/--apply", help="Only print the plan and exit"),
):
    """Deploy Quditto components with Helm.

    Behavior:
      - Single-cluster: pass `--kubeconfig` and omit `--multi-cluster`.
      - Multi-cluster: pass `--multi-cluster` and declare `clusters` + `targetCluster`/`defaultCluster` in the spec.
    """
    # 1) Load and validate spec
    try:
        data = yaml.safe_load(file.read_text())
        spec = QudittoDeploySpec.model_validate(data)
    except Exception as e:
        rprint(f"[bold red]Spec validation error:[/] {e}")
        raise typer.Exit(code=2)

    ns = (namespace or spec.namespace or "default").strip()
    repo_url = spec.charts.repo

    # 2) Group components by target cluster
    grouped = _collect_components(spec, multi_cluster=multi_cluster, kubeconfig=kubeconfig)

    if not grouped:
        rprint("[yellow]Nothing to deploy: no components present in spec.[/]")
        raise typer.Exit(code=0)

    # 3) Show plan
    _print_plan(ns, repo_url, grouped)
    if plan_only:
        rprint("[cyan]Plan complete (no changes applied).[/]")
        raise typer.Exit(code=0)

    # 4) Execute per cluster
    for (cluster_name, kc_path), items in grouped.items():
        rprint(f"\n[bold cyan]Target cluster:[/] {cluster_name}  [dim]({kc_path})[/]")
        helm = HelmClient(kubeconfig=kc_path)

        # Idempotent repo add/update
        if helm.repo_add("quditto", repo_url) != 0:
            raise typer.Exit(code=1)
        helm.repo_update()

        for release_name, comp in items:
            # Map placement (nodeName) + user values -> final values dict
            # Your `map_component_values` should inject:
            #   placement.useNodeName=true, placement.nodeName=<nodek8s>, and merge extra comp.values.
            final_values = map_component_values(comp.values, node_name=comp.nodek8s)

            # Convert dict -> ["a.b=c", "x.y=1", ...] for `helm --set`
            set_inline = dict_to_set_list(final_values)

            # Full chart reference (allow plain "qcontroller-v2" or "quditto/qcontroller-v2")
            chart_ref = comp.chart if comp.chart.startswith("quditto/") else f"quditto/{comp.chart}"

            if show_values:
                rprint(f"[dim]--set for {release_name}:[/]\n{final_values}")

            rprint(f"  • Installing/Upgrading [magenta]{release_name}[/] -> {chart_ref}  (ns: {ns})")
            rc = helm.install_or_upgrade(
                release=release_name,
                chart=chart_ref,
                namespace=ns,
                version=comp.version,
                set_inline=set_inline,
                dry_run=dry_run,
                create_namespace=True,
            )
            if rc != 0:
                rprint(f"[red]Helm install/upgrade failed for '{release_name}'.[/]")
                raise typer.Exit(code=rc)

    rprint("\n[green]Quditto deployment completed.[/]")


# -----------------------------------------------------------------------------
# quditto teardown
# -----------------------------------------------------------------------------
@app.command()
def teardown(
    file: Path = typer.Option(..., "-f", "--file", exists=True, readable=True, help="Quditto multi/single cluster spec YAML"),
    kubeconfig: Optional[Path] = typer.Option(None, "--kubeconfig", help="(single-cluster) kubeconfig path"),
    namespace: Optional[str] = typer.Option(None, "--namespace", help="Override namespace (spec.namespace default)"),
    multi_cluster: bool = typer.Option(False, "--multi-cluster/--no-multi-cluster", help="Enable multi-cluster mode"),
    dry_run: bool = typer.Option(False, "--dry-run/--no-dry-run", help="Helm uninstall dry-run"),
    keep_history: bool = typer.Option(False, "--keep-history/--no-keep-history", help="Helm uninstall --keep-history"),
    plan_only: bool = typer.Option(False, "--plan/--apply", help="Only print the plan and exit"),
):
    """Uninstall Quditto releases previously installed by the deploy.

    Strategy:
      - Read the same spec and determine which releases should exist.
      - Group them per cluster and uninstall those releases from the target namespace.
    """
    # 1) Load and validate spec
    try:
        data = yaml.safe_load(file.read_text())
        spec = QudittoDeploySpec.model_validate(data)
    except Exception as e:
        rprint(f"[bold red]Spec validation error:[/] {e}")
        raise typer.Exit(code=2)

    ns = (namespace or spec.namespace or "default").strip()

    # 2) Group components (we only need release names and targets)
    grouped = _collect_components(spec, multi_cluster=multi_cluster, kubeconfig=kubeconfig)
    if not grouped:
        rprint("[yellow]Nothing to tear down: no components present in spec.[/]")
        raise typer.Exit(code=0)

    # 3) Show plan (what will be uninstalled)
    for (cluster_name, kc_path), items in grouped.items():
        table = Table(
            title=f"Quditto teardown plan → cluster: {cluster_name}  (kubeconfig: {kc_path})",
            box=box.SIMPLE,
            show_header=True,
            header_style="bold",
        )
        table.add_column("Release")
        table.add_column("Namespace")
        for release, _comp in items:
            table.add_row(release, ns)
        rprint(table)

    if plan_only:
        rprint("[cyan]Plan complete (no changes applied).[/]")
        raise typer.Exit(code=0)

    # 4) Execute per cluster
    for (cluster_name, kc_path), items in grouped.items():
        rprint(f"\n[bold cyan]Target cluster:[/] {cluster_name}  [dim]({kc_path})[/]")
        helm = HelmClient(kubeconfig=kc_path)

        for release_name, _comp in items:
            rprint(f"  • Uninstalling [magenta]{release_name}[/] (ns: {ns})")
            rc = helm.uninstall(
                release=release_name,
                namespace=ns,
                keep_history=keep_history,
                dry_run=dry_run,
            )
            if rc != 0:
                rprint(f"[red]Helm uninstall failed for '{release_name}'.[/]")
                raise typer.Exit(code=rc)

    rprint("\n[green]Quditto teardown completed.[/]")

# -----------------------------------------------------------------------------
# quditto status
# -----------------------------------------------------------------------------
@app.command()
def status(
    file: Path = typer.Option(..., "-f", "--file", exists=True, readable=True, help="Quditto multi/single cluster spec YAML"),
    kubeconfig: Optional[Path] = typer.Option(None, "--kubeconfig", help="(single-cluster) kubeconfig path"),
    namespace: Optional[str] = typer.Option(None, "--namespace", help="Override namespace (spec.namespace default)"),
    multi_cluster: bool = typer.Option(False, "--multi-cluster/--no-multi-cluster", help="Enable multi-cluster mode"),
):
    """
    Show the runtime status of Quditto components:

      - Per component (release): chart, pod phase/ready, node name and node IP.
      - NodePort services: list of NodePorts exposed by each component.
    """
    # 1) Load and validate spec
    try:
        data = yaml.safe_load(file.read_text())
        spec = QudittoDeploySpec.model_validate(data)
    except Exception as e:
        rprint(f"[bold red]Spec validation error:[/] {e}")
        raise typer.Exit(code=2)

    ns = (namespace or spec.namespace or "default").strip()

    # 2) Group components by target cluster
    grouped = _collect_components(spec, multi_cluster=multi_cluster, kubeconfig=kubeconfig)
    if not grouped:
        rprint("[yellow]Nothing to show: no components present in spec.[/]")
        raise typer.Exit(code=0)

    # 3) For each cluster, query pods + services via kubectl and print a table
    for (cluster_name, kc_path), items in grouped.items():
        rprint(f"\n[bold cyan]Cluster:[/] {cluster_name}  [dim]({kc_path})[/]  Namespace: [magenta]{ns}[/]")

        kubectl = Kubectl(kubeconfig=kc_path)

        table = Table(
            title=f"Quditto status → cluster: {cluster_name}",
            box=box.SIMPLE,
            show_header=True,
            header_style="bold",
        )
        table.add_column("Component")        # Helm release name
        table.add_column("Chart")
        table.add_column("Pod")
        table.add_column("Pod IP")
        table.add_column("Phase/Ready")
        table.add_column("Node")
        table.add_column("Node IP")
        table.add_column("NodePorts")

        for release_name, comp in items:
            chart_ref = comp.chart if comp.chart.startswith("quditto/") else f"quditto/{comp.chart}"

            pods = kubectl.pods_by_app(ns, release_name)
            svc_obj = kubectl.service(ns, release_name)
            nodeports = Kubectl.nodeports(svc_obj)

            if nodeports:
                nodeports_str = ", ".join(
                    f'{p.get("name") or "-"}:{p["nodePort"]}'
                    for p in nodeports
                )
            else:
                nodeports_str = "-"

            if not pods:
                # No pods found for this release
                table.add_row(
                    release_name,   # Component
                    chart_ref,      # Chart
                    "-",            # Pod
                    "-",            # Pod IP
                    "NotFound",     # Phase/Ready
                    "-",            # Node
                    "-",            # Node IP
                    nodeports_str,  # NodePorts
                )
                continue

            # One row per pod
            for pod in pods:
                pod_name = pod.get("metadata", {}).get("name", "-")
                pod_ip = pod.get("status", {}).get("podIP") or "-"

                phase = pod.get("status", {}).get("phase", "Unknown")
                ready = Kubectl.pod_ready(pod)
                phase_ready = f"{phase}/{ready}"

                node_name = pod.get("spec", {}).get("nodeName")
                node_ip = "-"
                if node_name:
                    node_obj = kubectl.node(node_name)
                    if node_obj:
                        node_ip = Kubectl.node_ip(node_obj) or "-"

                table.add_row(
                    release_name,        # Component
                    chart_ref,           # Chart
                    pod_name,            # Pod
                    pod_ip,              # Pod IP
                    phase_ready,         # Phase/Ready
                    node_name or "-",    # Node
                    node_ip,             # Node IP
                    nodeports_str,       # NodePorts
                )




        rprint(table)
        rprint(
            "[dim]Hint: You can reach SSH/HTTP endpoints via node external IPs, e.g. "
            "ssh user@<node-ip> -p <nodePort>[/]"
        )
