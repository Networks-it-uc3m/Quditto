# qd2_bootstrap/utils/kubeone.py
import shlex
import subprocess
from pathlib import Path
from typing import List, Optional
from rich import print as rprint

class KubeOneClient:
    def __init__(self, workdir: Path | None = None):
        self.workdir = workdir

    def _run(self, cmd: List[str], env: Optional[dict] = None) -> int:
        rprint(f"[dim]{(str(self.workdir) if self.workdir else '.')}$ {' '.join(shlex.quote(c) for c in cmd)}[/]")
        proc = subprocess.Popen(
            cmd,
            cwd=(self.workdir or None),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        assert proc.stdout is not None
        for line in proc.stdout:
            print(line, end="")
        return proc.wait()

    def apply(
        self,
        manifest_path: Path,
        tfstate_path: Path | None = None,
        verbose: bool = True,
        auto_approve: bool = True,
    ) -> int:
        cmd = ["kubeone", "apply", "-m", str(manifest_path)]
        if tfstate_path:
            cmd += ["-t", str(tfstate_path)]
        if verbose:
            cmd += ["-v"]
        if auto_approve:
            cmd += ["-y"]
        return self._run(cmd)

    def reset(
        self,
        manifest_path: Path,
        verbose: bool = True,
        auto_approve: bool = True,   # <-- añadir este parámetro
    ) -> int:
        cmd = ["kubeone", "reset", "-m", str(manifest_path)]
        if verbose:
            cmd += ["-v"]
        if auto_approve:
            cmd += ["-y"]            # <-- y pasar -y a kubeone
        return self._run(cmd)
