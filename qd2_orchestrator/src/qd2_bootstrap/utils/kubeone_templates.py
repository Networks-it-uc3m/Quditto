def render_manifest(
    name: str,
    k8s_version: str,
    ssh_user: str,
    ssh_key: str,
    cp_addrs: list[str],
    worker_addrs: list[str],
    api_host: str,
    api_port: int,
    pod_subnet: str,
    svc_subnet: str,
    external_cni: bool,
    helm_releases: list[dict],
) -> str:
    """
    Render a KubeOneCluster manifest from parameters.
    """
    # KubeOne requires explicit empty objects when using external CNI
    cni_block = "external: {}" if external_cni else "canal: {}"
    # Build host entries
    def host_entries(addrs: list[str]) -> str:
        lines = []
        for a in addrs:
            lines.append(f"""    - publicAddress: ""
      privateAddress: {a}
      sshUsername: {ssh_user}
      sshPrivateKeyFile: {ssh_key}""")
        return "\n".join(lines) if lines else "    []"

    # Helm releases block
    helm_block = ""
    if helm_releases:
        helm_block = "\nhelmReleases:\n"
        for hr in helm_releases:
            helm_block += f"""  - chart: {hr['chart']}
    repoURL: {hr['repoURL']}
    namespace: {hr['namespace']}
    version: {hr['version']}
    values:
      - inline: {hr.get('values', {})}
"""

    return f"""apiVersion: kubeone.k8c.io/v1beta2
kind: KubeOneCluster
name: {name}

versions:
  kubernetes: "{k8s_version}"

cloudProvider:
  none: {{}}

controlPlane:
  hosts:
{host_entries(cp_addrs)}

staticWorkers:
  hosts:
{host_entries(worker_addrs)}

apiEndpoint:
  host: {api_host}
  port: {api_port}

clusterNetwork:
  cni:
    {cni_block}
  podSubnet: {pod_subnet}
  serviceSubnet: {svc_subnet}
{helm_block}"""
