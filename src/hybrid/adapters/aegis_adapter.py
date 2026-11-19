from __future__ import annotations

from collections import deque
from dataclasses import dataclass

from aegis.loader import load_snapshot

SOURCE_TYPES = {"iam_role", "internet", "external_account"}


class TargetNotFound(ValueError):
    """The protected resource is not in the graph, so it cannot be evaluated."""


@dataclass(frozen=True)
class AccessPath:
    source: str
    target: str
    nodes: tuple[str, ...]
    reasons: tuple[str, ...]


def load_graph(snapshot_path):
    return load_snapshot(str(snapshot_path))


def shortest_path(graph, start: str, target: str) -> AccessPath | None:
    queue = deque([(start, (start,), ())])
    seen = {start}
    while queue:
        cur, nodes, reasons = queue.popleft()
        for edge in graph.neighbors(cur):
            if edge.dst in seen:
                continue
            n = nodes + (edge.dst,)
            r = reasons + (f"{edge.kind}: {edge.reason}",)
            if edge.dst == target:
                return AccessPath(start, target, n, r)
            seen.add(edge.dst)
            queue.append((edge.dst, n, r))
    return None


def paths_to(graph, target: str) -> list[AccessPath]:
    if target not in graph.nodes:
        raise TargetNotFound(
            f"{target} not found in snapshot (no policy references it, so it cannot be evaluated)"
        )
    paths = []
    for node_id, node in graph.nodes.items():
        if node.type in SOURCE_TYPES:
            p = shortest_path(graph, node_id, target)
            if p:
                paths.append(p)
    return paths


def load_paths(snapshot_path, target: str) -> list[AccessPath]:
    return paths_to(load_graph(snapshot_path), target)
