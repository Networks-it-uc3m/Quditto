import shlex
import subprocess
import json
from pathlib import Path
from typing import List, Optional
from rich import print as rprint


class Kubectl:
    """Thin wrapper around kubectl to run simple queries with a given kubeconfig."""

    def __init__(self, kubeconfig: Path):
        self.kubeconfig = Path(kubeconfig)

    # ------------------------------------------------------------------
    # Low-level runners
    # ------------------------------------------------------------------
    def _cmd(self, args: List[str]) -> List[str]:
        return ["kubectl", "--kubeconfig", str(self.kubeconfig), *args]

    def _run(self, args: List[str]) -> int:
        """Run kubectl and stream output to stdout (human use)."""
        cmd = self._cmd(args)
        rprint(f"[dim]$ {' '.join(shlex.quote(c) for c in cmd)}[/]")
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        assert proc.stdout is not None
        for line in proc.stdout:
            print(line, end="")
        return proc.wait()

    def _run_json(self, args: List[str]) -> Optional[dict]:
        """Run kubectl expecting JSON output (machine use)."""
        cmd = self._cmd(args)
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
        except subprocess.CalledProcessError:
            return None
        try:
            return json.loads(proc.stdout)
        except json.JSONDecodeError:
            return None

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------
    def get_nodes(self) -> int:
        return self._run(["get", "nodes", "-o", "wide"])

    def get_core_health(self) -> int:
        return self._run(["get", "pods", "-n", "kube-system", "-o", "wide"])

    # ------------------------------------------------------------------
    # helpers for Quditto status
    # ------------------------------------------------------------------
    def pods_by_app(self, namespace: str, app: str) -> List[dict]:
        """Return pod objects (raw) matching label app=<app>."""
        data = self._run_json(
            ["get", "pods", "-n", namespace, "-l", f"app={app}", "-o", "json"]
        )
        return data.get("items", []) if data else []

    def service(self, namespace: str, name: str) -> Optional[dict]:
        """Return a Service object (raw JSON) or None."""
        return self._run_json(["get", "svc", name, "-n", namespace, "-o", "json"])

    def node(self, name: str) -> Optional[dict]:
        """Return a Node object (raw JSON) or None."""
        return self._run_json(["get", "node", name, "-o", "json"])

    # ------------------------------------------------------------------
    # Parsers for getting quditto status
    # ------------------------------------------------------------------
    @staticmethod
    def node_ip(node_obj: dict) -> Optional[str]:
        addrs = node_obj.get("status", {}).get("addresses", [])
        for t in ("ExternalIP", "InternalIP"):
            for a in addrs:
                if a.get("type") == t:
                    return a.get("address")
        return addrs[0]["address"] if addrs else None

    @staticmethod
    def pod_ready(pod_obj: dict) -> str:
        for c in pod_obj.get("status", {}).get("conditions", []):
            if c.get("type") == "Ready":
                return c.get("status", "?")
        return "?"

    @staticmethod
    def nodeports(service_obj: dict) -> List[dict]:
        if not service_obj:
            return []
        if service_obj.get("spec", {}).get("type") != "NodePort":
            return []
        ports = []
        for p in service_obj.get("spec", {}).get("ports", []):
            if "nodePort" in p:
                ports.append(
                    {
                        "name": p.get("name"),
                        "port": p.get("port"),
                        "targetPort": p.get("targetPort"),
                        "nodePort": p.get("nodePort"),
                    }
                )
        return ports
