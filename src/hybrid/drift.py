import hashlib


def fingerprint(f: dict) -> str:
    key = "|".join(
        [f["tenant_id"], f["rule_id"], f["requirement_id"], f["attack_path_id"]]
    )
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def _path_ref(f: dict) -> str:
    for e in f.get("evidence", []):
        if e.get("kind") == "graph_path":
            return e.get("ref", "")
    return ""


def _index(findings: list[dict]) -> dict[str, dict]:
    return {fingerprint(f): f for f in findings}


def compute_drift(old: list[dict], new: list[dict]) -> dict:
    o, n = _index(old), _index(new)
    new_keys = sorted(n.keys() - o.keys())
    resolved_keys = sorted(o.keys() - n.keys())
    persisting, changed = [], []
    for k in sorted(o.keys() & n.keys()):
        a, b = o[k], n[k]
        if a["severity"] != b["severity"] or _path_ref(a) != _path_ref(b):
            changed.append({
                "fingerprint": k,
                "attack_path_id": b["attack_path_id"],
                "before": {"severity": a["severity"], "path": _path_ref(a)},
                "after": {"severity": b["severity"], "path": _path_ref(b)},
            })
        else:
            persisting.append(k)
    return {
        "new": [{"fingerprint": k, "attack_path_id": n[k]["attack_path_id"]} for k in new_keys],
        "resolved": [{"fingerprint": k, "attack_path_id": o[k]["attack_path_id"]} for k in resolved_keys],
        "persisting": persisting,
        "changed": changed,
    }
