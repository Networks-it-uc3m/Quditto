from pydantic import BaseModel, Field, field_validator, model_validator
from typing import Optional
import re

NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")

def _name(v: str, what: str) -> str:
    if not NAME_RE.match(v):
        raise ValueError(f"{what} must include only letters, digits, hyphen (-) and underscore (_): {v!r}")
    return v

class OpenStackAuth(BaseModel):
    authUrl: str
    region: str
    userName: str
    password: Optional[str] = None
    tenantId: str
    domainName: str

class InfraSetup(BaseModel):
    workdir: Optional[str] = Field(default=None)
    clusterName: str
    countCp: int = Field(ge=1, default=1)
    countWorker: int = Field(ge=0, default=2)

    imageName: str
    flavorName: str
    keypairName: str
    networkUuid: str

    openstack: OpenStackAuth

    @field_validator("clusterName")
    @classmethod
    def _v_cluster(cls, v: str) -> str:
        return _name(v, "clusterName")

    @model_validator(mode="after")
    def _default_workdir(self):
        """If workdir is not given, default to ./.tf-build/<clusterName>"""
        if not self.workdir:
            self.workdir = f"./.tf-build/{self.clusterName}"
        return self

class InfraSpec(BaseModel):
    namespace: Optional[str] = None
    infraSetup: InfraSetup
