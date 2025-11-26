import shlex
import subprocess
from pathlib import Path
from typing import List
from rich import print as rprint

class Kubectl:
    """Thin wrapper around kubectl to run simple queries with a given kubeconfig."""

    def __init__(self, kubeconfig: Path):
        self.kubeconfig = Path(kubeconfig)

    def _run(self, args: List[str]) -> int:
        cmd = ["kubectl", "--kubeconfig", str(self.kubeconfig), *args]
        rprint(f"[dim]$ {' '.join(shlex.quote(c) for c in cmd)}[/]")
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        assert proc.stdout is not None
        for line in proc.stdout:
            print(line, end="")
        return proc.wait()

    def get_nodes(self) -> int:
        return self._run(["get", "nodes", "-o", "wide"])

    def get_core_health(self) -> int:
        return self._run(["get", "pods", "-n", "kube-system", "-o", "wide"])
