import typer
from qd2_bootstrap.utils.logging import setup_logging
from qd2_bootstrap.commands import infra, cluster, quditto
from qd2_bootstrap.utils import deps_installer

app = typer.Typer(no_args_is_help=True, add_completion=False)
app.add_typer(infra.app, name="infra", 
    help=(
        "Provision cloud infrastructure as virtual machines in an OpenStack "
        "environment using Terraform."
    )
)
app.add_typer(cluster.app, name="cluster",
    help=(
        "Install and configure kubeadm-based k8s clusters on SSH-accessible machines "
        "using KubeOne"
    )
)
app.add_typer(quditto.app, name="quditto", 
    help=(
        "Deploy tailored Quditto-related k8s artifacts (pods, services, etc.) "
        "to prepare subsequent quditto orchestration."
    )
)


@app.callback()
def main(verbose: int = typer.Option(0, "--verbose", "-v", count=True)):
    setup_logging(verbosity=verbose)

def run():
    app()

@app.command("deps")
def deps(
    install: bool = typer.Option(
        False,
        "--install",
        "-i",
        help="Automatically install any missing tools (Linux only, uses sudo).",
    )
):
    """
    Check (and optionally install) external CLI dependencies required by qd2_bootstrap:
    kubectl, helm, terraform, subctl.
    """
    deps_installer.ensure_linux()
    arch = deps_installer.detect_arch()

    print(f"Detected Linux architecture: {arch}\n")

    missing = deps_installer.get_missing_tools()
    if not missing:
        print("All required tools are already installed.")
        return

    print("Missing tools:\n")
    for t in missing:
        print(f"- {t.name}: {t.description}")

    if not install:
        print(
            "\nRun again with --install to automatically install these tools "
            "(will use sudo where needed)."
        )
        return

    print("\nStarting installation of missing tools...\n")
    for t in missing:
        print(f"[*] Installing {t.name}...")
        deps_installer.install_tool(t, arch)
        print(f"[+] {t.name} installation completed.\n")

if __name__ == "__main__":
    run()
