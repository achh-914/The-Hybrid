from __future__ import annotations

import argparse
import json
from pathlib import Path

from .adapters.aegis_adapter import load_paths
from .graph_rules import target_of, unauthorized_access
from .models import Requirement
from .remediation import advise


def scan(requirements, snapshot):
    results = []
    for req in requirements:
        paths = load_paths(snapshot, target_of(req))
        findings = unauthorized_access(req, paths)
        by_id = {f"path:{p.source}->{p.target}": p for p in paths}
        results.append((req, findings, by_id))
    return results


def render_report(results, snapshot) -> str:
    lines = [
        "# THE HYBRID: contract vs cloud report",
        "",
        f"Snapshot: `{snapshot}`",
        "",
        "Scope: identity policies and role chaining in the snapshot. "
        "Not evaluated: resource policies, SCPs, permission boundaries.",
        "",
    ]
    total = 0
    for req, findings, by_id in results:
        total += len(findings)
        lines += [
            f"## Clause `{req.clause_id}`",
            "",
            f"- Protected resource: `{req.resource_selector}`",
            f"- Allowed by contract: {', '.join(f'`{p}`' for p in req.allowed_principals)}",
            f"- Result: {len(findings)} unauthorized access path(s)"
            if findings
            else "- Result: no unauthorized access path found in this snapshot",
            "",
        ]
        for f in findings:
            p = by_id[f.attack_path_id]
            advice = advise(snapshot, p)
            lines += [
                f"### [{f.severity.value.upper()}] {p.source}",
                "",
                f"- Path: {' -> '.join(p.nodes)}",
                f"- Why: {'; '.join(p.reasons)}",
                "- Evidence:",
                *[f"  - {e.kind.value}: `{e.ref}` (sha256 {e.hash})" for e in f.evidence],
                f"- Suggested change: {advice.change}",
                f"- What-if: {advice.after}",
                "- Action: human approval required before any change.",
                "",
            ]
    lines.append(f"**Total findings: {total}**")
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("requirements", type=Path)
    ap.add_argument("--snapshot", type=Path, required=True)
    ap.add_argument("--out", type=Path, default=Path("out/report.md"))
    args = ap.parse_args(argv)

    data = json.loads(args.requirements.read_text())
    requirements = [Requirement.model_validate(x) for x in data]
    results = scan(requirements, args.snapshot)

    report = render_report(results, args.snapshot)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(report)
    print(report)
    return 1 if any(findings for _, findings, _ in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
