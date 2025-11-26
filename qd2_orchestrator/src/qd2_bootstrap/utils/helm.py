# qd2_bootstrap/utils/helm.py
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Iterable, List, Optional
from rich import print as rprint

def _run(cmd: List[str]) -> int:
    """Run a command and stream stdout/stderr; return exit code."""
    rprint(f"$ {' '.join(cmd)}")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    assert proc.stdout is not None
    for line in proc.stdout:
        print(line, end="")
    proc.wait()
    return proc.returncode

class HelmClient:
    """Thin wrapper around the `helm` CLI with verbose logging."""
    def __init__(self, kubeconfig: Path):
        self.kubeconfig = Path(kubeconfig).expanduser().resolve()

    # ---------- repo ops ----------
    def repo_add(self, name: str, url: str) -> int:
        cmd = ["helm", "--kubeconfig", str(self.kubeconfig),
               "repo", "add", name, url, "--force-update"]
        return _run(cmd)

    def repo_update(self) -> int:
        cmd = ["helm", "--kubeconfig", str(self.kubeconfig), "repo", "update"]
        return _run(cmd)

    # ---------- installs ----------
    def install_or_upgrade(
        self,
        release: str,
        chart: str,
        namespace: str,
        version: Optional[str] = None,
        set_inline: Optional[Iterable[str]] = None,
        values_files: Optional[Iterable[Path]] = None,
        create_namespace: bool = True,
        dry_run: bool = False,
        atomic: bool = False,
        wait: bool = False,
        timeout: Optional[str] = None,  # e.g., "10m"
    ) -> int:
        """
        Run: helm upgrade --install <release> <chart> --namespace <ns> ...
        """
        cmd = ["helm", "--kubeconfig", str(self.kubeconfig),
               "upgrade", "--install", release, chart,
               "--namespace", namespace]

        if version:
            cmd += ["--version", version]

        # --set key=val for each entry in set_inline
        if set_inline:
            for expr in set_inline:
                cmd += ["--set", expr]

        # -f values.yaml (optional, we mostly use --set inline)
        if values_files:
            for vf in values_files:
                cmd += ["-f", str(Path(vf).expanduser().resolve())]

        if create_namespace:
            cmd.append("--create-namespace")
        if atomic:
            cmd.append("--atomic")
        if wait:
            cmd.append("--wait")
        if timeout:
            cmd += ["--timeout", timeout]
        if dry_run:
            cmd.append("--dry-run")

        return _run(cmd)

    # ---------- uninstalls ----------
    def uninstall(
        self,
        release: str,
        namespace: str,
        keep_history: bool = False,
        dry_run: bool = False,
    ) -> int:
        cmd = ["helm", "--kubeconfig", str(self.kubeconfig),
               "uninstall", release, "--namespace", namespace]
        if keep_history:
            cmd.append("--keep-history")
        if dry_run:
            cmd.append("--dry-run")
        return _run(cmd)

    # ---------- listing ----------
    def list_releases(self, namespace: Optional[str] = None) -> int:
        cmd = ["helm", "--kubeconfig", str(self.kubeconfig), "list", "--all"]
        if namespace:
            cmd += ["--namespace", namespace]
        return _run(cmd)
