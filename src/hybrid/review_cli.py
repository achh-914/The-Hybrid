from __future__ import annotations

import argparse
import json
from pathlib import Path

from pydantic import ValidationError

from .requirements import (
    Approval,
    RequirementProposal,
    append_audit,
    approve,
    reject,
)


def review(proposals, reviewer, audit_path, ask=input, say=print):
    approved = []
    for p in proposals:
        say(f"\nClause {p.clause_number} (page {p.page}):\n{p.clause_text}")
        say(f"Resource in contract: {p.resource_hint}")
        say(f"Principals in contract: {', '.join(p.principals_hint)}")

        choice = ""
        while choice not in {"a", "r", "s"}:
            choice = ask("approve / reject / skip [a/r/s]: ").strip().lower()
        if choice == "s":
            continue
        if choice == "r":
            reason = ask("reason: ").strip() or "no reason given"
            append_audit(audit_path, reject(p, reviewer, reason))
            continue

        while True:
            selector = ask("resource (bucket:<name>): ").strip()
            raw = ask("allowed principals (role:<name>, comma separated): ")
            principals = tuple(x.strip() for x in raw.split(",") if x.strip())
            try:
                approval = Approval(
                    reviewer=reviewer,
                    resource_selector=selector,
                    allowed_principals=principals,
                )
                break
            except ValidationError as e:
                say(f"invalid: {e.errors()[0]['msg']}")

        requirement, entry = approve(p, approval)
        append_audit(audit_path, entry)
        approved.append(requirement)
    return approved


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("proposals", type=Path)
    ap.add_argument("--reviewer", required=True)
    ap.add_argument("--out", type=Path, default=Path("out/requirements.json"))
    ap.add_argument("--audit", type=Path, default=Path("out/audit.jsonl"))
    args = ap.parse_args(argv)

    data = json.loads(args.proposals.read_text())
    proposals = [RequirementProposal.model_validate(x) for x in data]
    approved = review(proposals, args.reviewer, args.audit)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps([r.model_dump(mode="json") for r in approved], indent=2)
    )
    print(f"\n{len(approved)} requirement(s) approved -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
