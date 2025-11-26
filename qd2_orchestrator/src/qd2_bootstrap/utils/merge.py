def deep_merge(a: dict, b: dict) -> dict:
    """
    Recursively merge dict b into dict a without mutating inputs.
    Conflict rule:
      - if both values are dicts -> merge recursively
      - otherwise -> b wins (explicit override)
    This allows user-provided values to be merged with generated placement
    in a predictable and safe way.
    """
    out = dict(a)  # shallow copy to avoid side effects
    for k, v in b.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out
