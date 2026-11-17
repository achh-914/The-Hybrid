import argparse
import os

from .store import Store


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("create-tenant")
    c.add_argument("name")
    args = ap.parse_args(argv)

    store = Store(os.getenv("HYBRID_DB", "hybrid.db"))
    tenant_id, api_key = store.create_tenant(args.name)
    print(f"tenant: {tenant_id}")
    print(f"api key (shown once, keep it safe): {api_key}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
