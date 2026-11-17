from __future__ import annotations

from dataclasses import dataclass

from .adapters.aegis_adapter import AccessPath, load_graph, shortest_path


@dataclass(frozen=True)
class Advice:
    change: str
    after: str


def _change_text(src: str, dst: str, kind: str, reason: str) -> str:
    if kind == "can_access":
        return f"Remove the S3 permission ({reason}) on {dst} from the policies of {src}."
    if kind == "can_assume" and reason.startswith("iam:PassRole"):
        return f"Remove iam:PassRole on {dst} from the policies of {src}, or restrict it to approved services."
    if kind == "can_assume" and reason.startswith("sts:AssumeRole"):
        return f"Remove sts:AssumeRole on {dst} from the policies of {src}, or narrow the trust policy of {dst}."
    if kind == "can_assume":
        return f"Narrow the trust policy of {dst} so that {src} is not trusted ({reason})."
    return f"Remove the permission '{kind}: {reason}' between {src} and {dst}."


def advise(snapshot_path, path: AccessPath) -> Advice:
    """Suggest cutting the first hop, then re-run the search on a copy of the graph."""
    src, dst = path.nodes[0], path.nodes[1]
    kind, _, reason = path.reasons[0].partition(": ")

    graph = load_graph(snapshot_path)
    graph.out[src] = [e for e in graph.out[src] if not (e.dst == dst and e.kind == kind)]
    remaining = shortest_path(graph, path.source, path.target)

    if remaining is None:
        after = f"After this change, {path.source} has no path to {path.target} in the snapshot."
    else:
        after = (
            f"After this change, {path.source} can still reach {path.target} "
            f"through {' -> '.join(remaining.nodes)}. More changes are needed."
        )
    return Advice(change=_change_text(src, dst, kind, reason), after=after)
