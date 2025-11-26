from pydantic import BaseModel, Field, field_validator, model_validator
from typing import List, Optional, Dict
import re

NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")

def _name(v: str, what: str) -> str:
    if not NAME_RE.match(v):
        raise ValueError(f"{what} must include only letters, digits, hyphen (-) and underscore (_): {v!r}")
    return v

class SSHConfig(BaseModel):
    user: str
    privateKeyFile: str

class ApiEndpoint(BaseModel):
    host: str
    port: int = 6443

class Networking(BaseModel):
    podSubnet: str
    serviceSubnet: str

class HostRef(BaseModel):
    privateAddress: str     # publicAddress can be added later if needed

class ExistingHosts(BaseModel):
    controlPlane: List[HostRef]
    workers: List[HostRef] = Field(default_factory=list)

class FromInfra(BaseModel):
    workdir: str   # points to the Terraform workdir (we'll read outputs)

class HelmRelease(BaseModel):
    chart: str
    repoURL: str
    namespace: str
    version: str
    values: Dict = Field(default_factory=dict)

class ClusterSetup(BaseModel):
    name: str
    kubernetesVersion: str
    ssh: SSHConfig
    networking: Networking
    apiEndpoint: ApiEndpoint
    cni: Dict = Field(default_factory=dict)
    existingHosts: Optional[ExistingHosts] = None
    fromInfra: Optional[FromInfra] = None
    helmReleases: List[HelmRelease] = Field(default_factory=list)

    @field_validator("name")
    @classmethod
    def _v_name(cls, v: str) -> str:
        return _name(v, "clusterSetup.name")

    @model_validator(mode="after")
    def _one_mode(self):
        if not self.existingHosts and not self.fromInfra:
            raise ValueError("You must set either 'existingHosts' or 'fromInfra'")
        if self.existingHosts and self.fromInfra:
            raise ValueError("Use only one: 'existingHosts' or 'fromInfra'")
        return self

class ClusterSpec(BaseModel):
    clusterSetup: ClusterSetup
