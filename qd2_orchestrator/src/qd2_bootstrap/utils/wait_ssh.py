import subprocess, time, shlex
from pathlib import Path
from typing import Iterable
from rich import print as rprint

def ssh_ready(host: str, user: str, key: Path, timeout_s: int = 10) -> bool:
    cmd = [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-i", str(key),
        f"{user}@{host}",
        "true",
    ]
    try:
        proc = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout_s, check=False)
        return proc.returncode == 0
    except Exception:
        return False

def wait_ssh_all(hosts: Iterable[str], user: str, key: Path, timeout_total_s: int = 300, every_s: int = 5) -> bool:
    """Poll all hosts until SSH success or timeout. Returns True if all became ready."""
    deadline = time.time() + timeout_total_s
    pending = set(hosts)
    while time.time() < deadline and pending:
        ready = []
        for h in list(pending):
            if ssh_ready(h, user, key, timeout_s=10):
                ready.append(h)
        for h in ready:
            pending.remove(h)
            rprint(f"[green]SSH ready:[/] {h}")
        if pending:
            time.sleep(every_s)
    if pending:
        rprint(f"[red]Timed out waiting SSH on:[/] {', '.join(sorted(pending))}")
        return False
    return True
