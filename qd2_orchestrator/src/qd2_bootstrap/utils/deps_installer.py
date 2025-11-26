import platform
import shutil
import subprocess
from dataclasses import dataclass
from typing import List


@dataclass
class Tool:
    name: str
    description: str


REQUIRED_TOOLS: List[Tool] = [
    Tool(
        name="kubectl",
        description="Kubernetes command-line tool",
    ),
    Tool(
        name="helm",
        description="Helm package manager for Kubernetes",
    ),
    Tool(
        name="terraform",
        description="Terraform infrastructure-as-code CLI",
    ),
    Tool(
        name="subctl",
        description="Submariner CLI for multi-cluster networking",
    ),
]


def ensure_linux() -> None:
    if platform.system().lower() != "linux":
        raise RuntimeError("This installer is only supported on Linux hosts.")


def detect_arch() -> str:
    """
    Return 'amd64' or 'arm64' depending on the CPU architecture.
    Raise for anything else (you can add more mappings later if needed).
    """
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        return "amd64"
    if machine in ("aarch64", "arm64"):
        return "arm64"
    raise RuntimeError(f"Unsupported CPU architecture: {machine}")


def is_installed(name: str) -> bool:
    return shutil.which(name) is not None


def get_missing_tools() -> List[Tool]:
    return [t for t in REQUIRED_TOOLS if not is_installed(t.name)]


def _run_shell(cmd: str) -> None:
    """
    Run a shell command, streaming output.
    Raise if it fails.
    """
    print(f"\n[+] Running:\n{cmd}\n")
    result = subprocess.run(cmd, shell=True)
    if result.returncode != 0:
        raise RuntimeError(f"Command failed with exit code {result.returncode}")


def install_kubectl(arch: str) -> None:
    """
    Install kubectl on Linux using the official Kubernetes binary + checksum
    method, following the documentation on kubernetes.io.

    arch: "amd64" or "arm64"
    """
    cmd = (
        # 1) Download the latest stable release for the given arch
        'curl -LO "https://dl.k8s.io/release/$(curl -L -s '
        'https://dl.k8s.io/release/stable.txt)/bin/linux/{arch}/kubectl" && '

        # 2) Download the corresponding checksum
        'curl -LO "https://dl.k8s.io/release/$(curl -L -s '
        'https://dl.k8s.io/release/stable.txt)/bin/linux/{arch}/kubectl.sha256" && '

        # 3) Validate the binary with sha256sum
        'echo "$(cat kubectl.sha256)  kubectl" | sha256sum --check && '

        # 4) Install kubectl into /usr/local/bin with proper permissions
        'sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl && '

        # 5) Clean up checksum file
        'rm kubectl.sha256 && '

        # 6) Show the installed client version
        'kubectl version --client'
    ).format(arch=arch)

    _run_shell(cmd)



def install_helm() -> None:
    """
    Install Helm using the official install script (detects arch internally).
    """
    cmd = "curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash"
    _run_shell(cmd)


def install_terraform() -> None:
    """
    Install Terraform using the official HashiCorp APT repository
    (Debian/Ubuntu-style). Requires sudo.
    """
    cmd = (
        # 1) Make sure system and prerequisites are ready
        "sudo apt-get update && "
        "sudo apt-get install -y gnupg software-properties-common && "

        # 2) Install HashiCorp's GPG key
        "wget -O- https://apt.releases.hashicorp.com/gpg | "
        "gpg --dearmor | "
        "sudo tee /usr/share/keyrings/hashicorp-archive-keyring.gpg > /dev/null && "

        # 3) Add the official HashiCorp repo (with arch and Ubuntu codename)
        "echo \"deb [arch=$(dpkg --print-architecture) "
        "signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] "
        "https://apt.releases.hashicorp.com "
        "$(grep -oP '(?<=UBUNTU_CODENAME=).*' /etc/os-release || lsb_release -cs) main\" "
        "| sudo tee /etc/apt/sources.list.d/hashicorp.list > /dev/null && "

        # 4) Update and install Terraform
        "sudo apt-get update && "
        "sudo apt-get install -y terraform"
    )

    _run_shell(cmd)



from pathlib import Path
import os


def install_subctl() -> None:
    """
    Install subctl using the official get.submariner.io script.
    The binary is installed into ~/.local/bin.
    """
    # 1) Run the official installer
    cmd = "curl -Ls https://get.submariner.io | bash"
    _run_shell(cmd)

    subctl_path = Path.home() / ".local" / "bin" / "subctl"

    if not subctl_path.exists():
        raise RuntimeError(
            "subctl installation finished but binary was not found at "
            f"{subctl_path}"
        )

    print(f"[+] subctl installed at {subctl_path}")

    local_bin = str(subctl_path.parent)
    current_path = os.environ.get("PATH", "")

    # 2) Ensure ~/.local/bin is in PATH for current execution
    if local_bin not in current_path:
        os.environ["PATH"] = f"{current_path}:{local_bin}"
        print(f"[+] Added {local_bin} to PATH for current session")

    # 3) Ensure ~/.local/bin is added persistently
    profile = Path.home() / ".profile"
    export_line = "export PATH=$PATH:~/.local/bin"

    if profile.exists():
        profile_content = profile.read_text()
        if export_line not in profile_content:
            with profile.open("a") as f:
                f.write(f"\n{export_line}\n")
            print(f"[+] Persisted PATH update in {profile}")
        else:
            print(f"[=] PATH already configured in {profile}")
    else:
        # Some systems may not have ~/.profile yet
        profile.write_text(f"{export_line}\n")
        print(f"[+] Created {profile} and added PATH configuration")



def install_tool(tool: Tool, arch: str) -> None:
    if tool.name == "kubectl":
        install_kubectl(arch)
    elif tool.name == "helm":
        install_helm()
    elif tool.name == "terraform":
        install_terraform()
    elif tool.name == "subctl":
        install_subctl()
    else:
        raise RuntimeError(f"No installer defined for tool: {tool.name}")
