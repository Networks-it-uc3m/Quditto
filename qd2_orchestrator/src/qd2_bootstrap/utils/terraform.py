import subprocess
import os
import json
from pathlib import Path
from typing import Optional, Dict
from rich import print as rprint


class TerraformClient:
    """
    Wrapper para comandos Terraform: init, apply, destroy y output.
    """

    def __init__(self, workdir: Path, extra_env: Optional[Dict[str, str]] = None):
        self.workdir = Path(workdir)
        self.env = os.environ.copy()
        if extra_env:
            self.env.update(extra_env)

    def _run(self, args, capture_output=True) -> int:
        cmd = ["terraform"] + args
        rprint(f"{self.workdir}$ {' '.join(cmd)}")
        proc = subprocess.Popen(
            cmd,
            cwd=self.workdir,
            env=self.env,
            stdout=(subprocess.PIPE if capture_output else None),
            stderr=(subprocess.PIPE if capture_output else None),
        )
        out, err = proc.communicate()
        if capture_output and out:
            print(out.decode())
        if capture_output and err:
            print(err.decode())
        return proc.returncode

    def init(self) -> int:
        """Ejecuta terraform init"""
        return self._run(["init", "-input=false"])

    def apply(self, auto_approve: bool = False) -> int:
        """Ejecuta terraform apply"""
        args = ["apply", "-input=false"]
        if auto_approve:
            args.append("-auto-approve")
        return self._run(args)

    def destroy(self, auto_approve: bool = False) -> int:
        """Ejecuta terraform destroy"""
        args = ["destroy", "-input=false"]
        if auto_approve:
            args.append("-auto-approve")
        return self._run(args)

    def output_json(self) -> dict:
        """Obtiene la salida en JSON de terraform output"""
        cmd = ["terraform", "output", "-json"]
        proc = subprocess.Popen(
            cmd, cwd=self.workdir, env=self.env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        out, err = proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError(f"terraform output failed: {err.decode()}")
        return json.loads(out.decode())
