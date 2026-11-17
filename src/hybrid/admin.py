import argparse
import os
import sys

from .auth import Role
from .store import Store


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("create-tenant", help="create a tenant with its first (admin) key")
    c.add_argument("name")

    k = sub.add_parser("create-key", help="create an API key for a user of a tenant")
    k.add_argument("tenant_id")
    k.add_argument("user_id")
    k.add_argument(
        "--role",
        choices=[r.value for r in Role],
        default=Role.VIEWER.value,
        help="default: viewer (least privilege)",
    )

    args = ap.parse_args(argv)
    store = Store(os.getenv("HYBRID_DB", "hybrid.db"))

    if args.cmd == "create-tenant":
        tenant_id, api_key = store.create_tenant(args.name)
        print(f"tenant: {tenant_id}")
        print("role: admin")
        print(f"api key (shown once, keep it safe): {api_key}")
        return 0

    try:
        api_key = store.create_key(args.tenant_id, args.user_id, args.role)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(f"tenant: {args.tenant_id}")
    print(f"user: {args.user_id}")
    print(f"role: {args.role}")
    print(f"api key (shown once, keep it safe): {api_key}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
