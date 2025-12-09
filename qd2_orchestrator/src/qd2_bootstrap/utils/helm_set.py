# qd2_bootstrap/utils/helm_set.py
from __future__ import annotations

from typing import Any, Dict, List

def _to_scalar(val: Any) -> str:
    """
    Convert a Python value into a Helm-friendly scalar for --set.
    Notes:
      - bool -> "true"/"false"
      - None -> ""
      - numbers -> str(number)
      - str -> as-is (no quoting needed because we pass args list, not a shell string)
      - list[scalars] -> {a,b,c}  (Helm list literal)
      - dict -> not supported here (must be flattened by caller)
    """
    if isinstance(val, bool):
        return "true" if val else "false"
    if val is None:
        return ""
    if isinstance(val, (int, float)):
        return str(val)
    if isinstance(val, str):
        return val
    if isinstance(val, (list, tuple)):
        # Only scalar lists are supported here
        items = ",".join(_to_scalar(x) for x in val)
        return "{" + items + "}"
    # Fallback: stringify
    return str(val)

def _flatten(prefix: str, obj: Any, out: List[str]) -> None:
    """
    Recursively flatten a nested dict into helm --set key=value pairs.

    Supports:
      - dict: a.b.c=value
      - list of scalars: a={1,2,3}
      - list of dicts: a[0].x=..., a[1].y=...
    """
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else k
            _flatten(key, v, out)

    elif isinstance(obj, list):
        # If it's a list of non-dicts -> treat as scalar list: a={1,2,3}
        if not obj or all(not isinstance(x, dict) for x in obj):
            out.append(f"{prefix}={_to_scalar(obj)}")
        else:
            # List of dicts (like service.ports): use indexed keys a[0].name, a[1].port, ...
            for idx, item in enumerate(obj):
                key = f"{prefix}[{idx}]"
                _flatten(key, item, out)

    else:
        out.append(f"{prefix}={_to_scalar(obj)}")


def dict_to_set_list(values: Dict[str, Any]) -> List[str]:
    """
    Turn a values dict into a list of --set expressions for Helm.

    Example:
      {"placement": {"useNodeName": true, "nodeName": "worker-1"},
       "l2sm": {"enabled": false}}
    becomes:
      ["placement.useNodeName=true",
       "placement.nodeName=worker-1",
       "l2sm.enabled=false"]
    """
    flattened: List[str] = []
    _flatten("", values, flattened)
    return flattened
