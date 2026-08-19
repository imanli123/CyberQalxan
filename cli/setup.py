from __future__ import annotations
import json
import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import settings
from common.tpm_identity import create_identity


def ask(prompt: str, default: str = "") -> str:
    value = input(f"{prompt} [{default}]: ").strip()
    return value or default


def discover_peers(port: int, timeout: int = 5) -> list:
    """F1: broadcast `CQ_DISCOVER` over UDP and collect replying sentinels."""
    peers = set()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(timeout)
    try:
        sock.bind(("", port))
        sock.sendto(b"CQ_DISCOVER", ("<broadcast>", port))
        while True:
            try:
                data, addr = sock.recvfrom(64)
                if data == b"CQ_SENTINEL":
                    peers.add(addr[0])
            except socket.timeout:
                break
    except OSError as exc:
        print(f"[discover] failed: {exc}")
    finally:
        sock.close()
    return sorted(peers)


def setup_identities(kind: str, cluster_password: str):
    oracle_identity = create_identity(kind, settings.ORACLE_IDENTITY_KEY_PATH, cluster_password or None)
    oracle_identity.save_public_key(settings.ORACLE_PUBLIC_KEY_PATH)
    sentinel_identity = create_identity(kind, settings.SENTINEL_IDENTITY_KEY_PATH, cluster_password or None)
    print(f"[identity] oracle key -> {settings.ORACLE_IDENTITY_KEY_PATH}")
    print(f"[identity] oracle public key -> {settings.ORACLE_PUBLIC_KEY_PATH}")
    print(f"[identity] sentinel key -> {settings.SENTINEL_IDENTITY_KEY_PATH}")
    return sentinel_identity.get_public_key_pem()


def write_env(values: dict):
    env_path = Path(settings.PROJECT_ROOT) / ".env"
    existing = {}
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                key, _, value = line.partition("=")
                existing[key.strip()] = value.strip()
    existing.update(values)
    env_path.write_text("\n".join(f"{k}={v}" for k, v in existing.items()) + "\n")
    print(f"[config] wrote {env_path}")


def main():
    print("=== CyberQalxan setup ===")
    siem_type = ask("SIEM type (wazuh/splunk)", "wazuh").strip().lower()
    if siem_type not in ("wazuh", "splunk"):
        print("Only wazuh/splunk are supported")
        return

    values = {"CQ_SIEM_TYPE": siem_type}
    if siem_type == "wazuh":
        values["CQ_WAZUH_INDEXER_PASSWORD"] = ask("Wazuh indexer password", "change-me")
        values["CQ_WAZUH_WEBHOOK_TOKEN"] = ask("Webhook shared token", "change-me")
    else:
        values["CQ_SPLUNK_HEC_TOKEN"] = ask("Splunk HEC token", "change-me")

    peers = discover_peers(settings.UDP_DISCOVERY_PORT)
    if peers:
        print(f"[discover] found sentinels: {', '.join(peers)}")
        if ask("Use discovered peers?", "y").lower() == "y":
            node_ips = peers
        else:
            node_ips = ask("Sentinel IPs (comma separated)", ",".join(settings.SENTINEL_NODE_IPS)).replace(" ", "").split(",")
    else:
        print("[discover] no sentinels responded; enter manually")
        node_ips = ask("Sentinel IPs (comma separated)", ",".join(settings.SENTINEL_NODE_IPS)).replace(" ", "").split(",")
    node_ips = [ip for ip in node_ips if ip]

    cluster_password = ask("Cluster password (encrypts identity keys)", "")
    admin_password = ask("Cluster admin password (authorizes node ops)", "change-me")
    identity_kind = ask("Identity kind (auto/tpm/file)", "auto").strip().lower()

    sentinel_pem = setup_identities(identity_kind, cluster_password)

    registry_path = Path(settings.SENTINEL_PUBLIC_KEY_REGISTRY_PATH)
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    registry_path.write_text(json.dumps({ip: sentinel_pem for ip in node_ips}, indent=2))
    print(f"[config] wrote sentinel registry -> {registry_path}")

    values.update({
        "CQ_IDENTITY_KIND": identity_kind,
        "CQ_CLUSTER_PASSWORD": cluster_password,
        "CQ_CLUSTER_ADMIN_PASSWORD": admin_password,
        "CQ_SENTINEL_IPS": ",".join(node_ips),
    })
    write_env(values)
    print("\nSetup complete. Restart daemons to pick up config, then start the oracle, sentinels and auditor.")


if __name__ == "__main__":
    main()
