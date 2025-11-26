# qd2_bootstrap/utils/mapping.py
from __future__ import annotations

from typing import Dict, Any
from qd2_bootstrap.utils.merge import deep_merge

def map_component_values(user_values: Dict[str, Any] | None, node_name: str) -> Dict[str, Any]:
    """
    Build the final Helm values for a component.

    - Injects placement knobs derived from the target node (`node_name`).
    - Deep-merges user-provided overrides on top.

    Charts convention assumed:
      placement:
        useNodeName: true
        nodeName: "<node>"
        nodeSelector: {}     # (optional/ignored if useNodeName=true)

    Args:
      user_values: dict with user overrides (can be None).
      node_name: Kubernetes nodeName where we want to pin the workload.

    Returns:
      A dict with the merged values, suitable to serialize to --set.
    """
    base: Dict[str, Any] = {
        "placement": {
            "useNodeName": True,
            "nodeName": node_name,
        }
    }
    return deep_merge(base, user_values or {})
