from __future__ import annotations
import argparse
import hashlib
import hmac
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import settings


def _sign(payload: dict) -> str:
    body = json.dumps(payload, sort_keys=True)
    return hmac.new(settings.CLUSTER_ADMIN_PASSWORD.encode(), body.encode(), hashlib.sha256).hexdigest()


def cmd_status(args):
    targets = [args.target] if args.target else settings.SENTINEL_NODE_IPS
    for ip in targets:
        try:
            resp = requests.get(f"http://{ip}:{settings.SENTINEL_API_PORT}/health", timeout=5)
            if resp.status_code == 200:
                print(f"{ip}: OK {resp.json()}")
            else:
                print(f"{ip}: HTTP {resp.status_code}")
        except Exception as exc:
            print(f"{ip}: unreachable ({exc!r})")


def cmd_audit(args):
    from auditor.stateful_auditor import AuditDaemon

    daemon = AuditDaemon()
    now = datetime.utcnow()
    end = now - timedelta(seconds=settings.AUDITOR_VANGUARD_DELAY_SECONDS)
    start = end - timedelta(seconds=60)
    daemon._audit_window(start.isoformat(), end.isoformat())
    print("Audit pass complete.")


def _admin_request(action: str, ip: str, seed: str):
    payload = {"action": action, "ip": ip, "timestamp": datetime.utcnow().isoformat()}
    payload["signature"] = _sign({"action": payload["action"], "ip": payload["ip"], "timestamp": payload["timestamp"]})
    resp = requests.post(
        f"http://{seed}:{settings.SENTINEL_API_PORT}/admin/{action}",
        json=payload,
        timeout=10,
    )
    print(resp.status_code, resp.text)


def cmd_add_node(args):
    _admin_request("add-node", args.ip, args.seed or settings.SEED_NODE_IP)


def cmd_remove_node(args):
    _admin_request("evict", args.ip, args.seed or settings.SEED_NODE_IP)


def main():
    parser = argparse.ArgumentParser(prog="manage", description="CyberQalxan management CLI")
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("status", help="show sentinel cluster status")
    p.add_argument("--target", help="specific sentinel IP")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("audit", help="run a one-shot audit pass over the last minute")
    p.set_defaults(func=cmd_audit)

    p = sub.add_parser("add-node", help="add a sentinel to the cluster")
    p.add_argument("ip")
    p.add_argument("--seed", help="seed sentinel IP")
    p.set_defaults(func=cmd_add_node)

    p = sub.add_parser("remove-node", help="evict a sentinel from the cluster")
    p.add_argument("ip")
    p.add_argument("--seed", help="seed sentinel IP")
    p.set_defaults(func=cmd_remove_node)

    args = parser.parse_args()
    if args.command:
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()