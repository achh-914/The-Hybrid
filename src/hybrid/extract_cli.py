from __future__ import annotations

import json
import sys
from pathlib import Path

from .extraction import extract_proposals
from .providers.gemini import GeminiClient


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: python -m hybrid.extract_cli <contract.md>")
        return 2
    path = Path(args[0])
    proposals = extract_proposals(path.read_text(), GeminiClient(), "demo-tenant", path.stem)
    print(json.dumps([p.model_dump(mode="json") for p in proposals], indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
