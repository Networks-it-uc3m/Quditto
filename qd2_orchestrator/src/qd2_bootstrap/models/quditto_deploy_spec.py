from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Naming helpers
# ---------------------------------------------------------------------------
# Relaxed identifier: letters (any case), digits, hyphen (-), underscore (_)
NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")


def _name(v: str, what: str) -> str:
    """Validate identifiers against a relaxed pattern.

    Accepts: letters (any case), digits, hyphen (-), underscore (_).
    Raises ValueError on mismatch to stop invalid specs early.
    """
    if not NAME_RE.match(v):
        raise ValueError(
            f"{what} must include only letters, digits, hyphen (-) and underscore (_): {v!r}"
        )
    return v


# ---------------------------------------------------------------------------
# Leaf models
# ---------------------------------------------------------------------------
class ChartsConfig(BaseModel):
    """Global chart source (classic Helm repo URL)."""
    repo: str  # e.g., "https://borjand.github.io/k8s-qudittov2-deployment/"


class ClusterRef(BaseModel):
    """Reference to a deployable cluster, resolved by a kubeconfig path."""
    kubeconfig: Path

    @field_validator("kubeconfig")
    @classmethod
    def _v_kubeconfig(cls, v: Path) -> Path:
        # We *do not* require the file to exist at validation time,
        # because validation may run on a different machine/CI step.
        # The CLI should check existence before deploying.
        return v


class ComponentRef(BaseModel):
    """One deployable component: placement params + chart reference + optional values.

    Fields:
      - nodek8s: target Kubernetes nodeName (your charts translate this into placement.* values)
      - chart: Helm chart name (e.g., "qcontroller-v2")
      - version: optional chart version
      - values: dict of overrides merged/mapped into your chart values
      - targetCluster: optional logical cluster name; if omitted, defaultCluster is used
    """
    nodek8s: str
    chart: str
    version: Optional[str] = None
    values: Dict = Field(default_factory=dict)
    targetCluster: Optional[str] = None  # <-- multi-cluster hook

    @field_validator("nodek8s")
    @classmethod
    def _v_nodek8s(cls, v: str) -> str:
        return _name(v, "nodek8s")

    @field_validator("chart")
    @classmethod
    def _v_chart(cls, v: str) -> str:
        # Chart names like "qcontroller-v2" are fine.
        # If you later allow "repo/name" (e.g., "quditto/qcontroller-v2"),
        # consider relaxing/duplicating validation accordingly.
        return _name(v, "chart")


class QNodeRef(ComponentRef):
    """A Quditto node also carries a logical unique name."""
    name: str

    @field_validator("name")
    @classmethod
    def _v_name(cls, v: str) -> str:
        return _name(v, "qnode.name")


# ---------------------------------------------------------------------------
# Grouping for Quditto components
# ---------------------------------------------------------------------------
class QudittoSetup(BaseModel):
    """Top-level grouping for Quditto components.

    Each child is optional; the CLI deploys only the ones present in the spec.
    """
    qcontroller: Optional[ComponentRef] = None
    qorchestrator: Optional[ComponentRef] = None
    qnodes: List[QNodeRef] = Field(default_factory=list)

    @field_validator("qnodes")
    @classmethod
    def _unique_qnode_names(cls, items: List[QNodeRef]) -> List[QNodeRef]:
        """Ensure qnode names are unique within the spec."""
        seen = set()
        for it in items:
            if it.name in seen:
                raise ValueError(f"duplicated qnode name: {it.name}")
            seen.add(it.name)
        return items


# ---------------------------------------------------------------------------
# Full spec (single or multi-cluster)
# ---------------------------------------------------------------------------
class QudittoDeploySpec(BaseModel):
    """Declarative deployment spec for Quditto.

    This model only validates structure and naming. It does **not** perform
    any Kubernetes/Helm calls. The CLI layer should:
      - check that kubeconfigs exist (when needed),
      - resolve target cluster per component (see helpers below),
      - perform Helm repo add/update and install/upgrade per cluster.
    """
    namespace: Optional[str] = None                 # defaults later in CLI (e.g., "default")
    charts: ChartsConfig                            # repo URL for charts
    qudittoSetup: QudittoSetup                      # components to deploy

    # --- Multi-cluster support ---
    # Map of logical cluster name -> kubeconfig file path
    clusters: Dict[str, ClusterRef] = Field(default_factory=dict)

    # Default cluster name to use if a component does not set `targetCluster`
    defaultCluster: Optional[str] = None

    # --------------------------
    # Validators / sanity checks
    # --------------------------
    @field_validator("namespace")
    @classmethod
    def _v_ns(cls, v: Optional[str]) -> Optional[str]:
        # Allow None (CLI can set "default" later), otherwise validate
        return _name(v, "namespace") if v else v

    @field_validator("defaultCluster")
    @classmethod
    def _check_default_exists(cls, v: Optional[str], info) -> Optional[str]:
        """If defaultCluster is set, make sure it exists in `clusters`."""
        if v is None:
            return v
        clusters = info.data.get("clusters", {})
        if v not in clusters:
            raise ValueError(f"defaultCluster '{v}' not found in clusters map")
        return v

    # --------------------------
    # Convenience helper methods
    # --------------------------
    def resolve_target_cluster(self, comp: ComponentRef) -> str:
        """Return the logical cluster name for a component.

        Precedence:
          1) comp.targetCluster, if set
          2) self.defaultCluster, if set
        Raises ValueError if no cluster can be resolved or if it is unknown.
        """
        target = comp.targetCluster or self.defaultCluster
        if not target:
            raise ValueError("No targetCluster set and no defaultCluster specified")
        if target not in self.clusters:
            raise ValueError(f"targetCluster '{target}' not defined under clusters")
        return target

    def kubeconfig_for(self, cluster_name: str) -> Path:
        """Return the absolute kubeconfig Path for a given logical cluster name.

        The CLI should check `Path.exists()` before using it and provide a clear error
        if the file is missing/inaccessible.
        """
        ref = self.clusters.get(cluster_name)
        if not ref:
            raise ValueError(f"cluster '{cluster_name}' not found")
        return Path(ref.kubeconfig).expanduser().resolve()
