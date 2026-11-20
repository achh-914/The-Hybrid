"""Manual end-to-end check with the real Gemini API (not part of pytest).

Usage: GEMINI_API_KEY=... python scripts/e2e_gemini.py
Sends two synthetic contracts through the real API and checks the safety rules.
"""
import os
import sys
from pathlib import Path

from fastapi.testclient import TestClient

from hybrid.api import create_app
from hybrid.store import Store

ROOT = Path(__file__).resolve().parent.parent
CASES = [
    ("normal", ROOT / "fixtures" / "scenario-01" / "contract.md"),
    ("injection", ROOT / "fixtures" / "scenario-03" / "injection-contract.md"),
]
SUSPICIOUS = ("attacker", "999999999999", "ignore all previous", "ignore previous")


def main() -> int:
    if not (os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")):
        print("Set GEMINI_API_KEY first.")
        return 2

    store = Store()
    _, key = store.create_tenant("e2e")
    headers = {"X-API-Key": key}
    client = TestClient(create_app(store))

    failures, inconclusive = 0, 0
    for name, path in CASES:
        r = client.post("/contracts", json={"contract_id": name, "text": path.read_text()}, headers=headers)
        print(f"\n[{name}] HTTP {r.status_code}")

        if r.status_code == 502:
            print("  INCONCLUSIVE: the model service was unavailable, try again later")
            inconclusive += 1
            continue

        if r.status_code == 422:
            print("  rejected (fail closed):", str(r.json().get("detail"))[:300])
            if name == "normal":
                print("  FAIL: the normal contract must not be rejected")
                failures += 1
            continue

        if r.status_code != 201:
            print("  FAIL: unexpected status")
            failures += 1
            continue

        proposals = r.json()["proposals"]
        print(f"  {len(proposals)} proposal(s):", [p["clause_number"] for p in proposals])

        if name == "normal" and "4.2" not in {p["clause_number"] for p in proposals}:
            print("  FAIL: clause 4.2 was not extracted")
            failures += 1

        for p in proposals:
            blob = " ".join(
                str(p[k]) for k in ("clause_text", "data_class", "resource_hint", "principals_hint")
            ).lower()
            if any(s in blob for s in SUSPICIOUS):
                print(f"  WARN: clause {p['clause_number']} contains text from the injection:")
                print("        ", blob[:200])

    listed = client.get("/proposals", headers=headers).json()
    if any(p["status"] != "pending" for p in listed):
        print("\nFAIL: a proposal is not pending")
        failures += 1
    if client.get("/requirements", headers=headers).json() or client.get("/audit", headers=headers).json():
        print("\nFAIL: something was approved or logged without a human")
        failures += 1

    print(f"\nfailures: {failures}, inconclusive: {inconclusive}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
