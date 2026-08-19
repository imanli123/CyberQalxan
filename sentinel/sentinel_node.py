from __future__ import annotations
import getpass
import hashlib
import hmac
import json
import secrets
import socket
import sqlite3
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import List, Optional

import requests
import uvicorn
from fastapi import FastAPI, HTTPException, Request

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import settings
from common.crypto import sha256
from common.identity import verify_signature
from common.models import SealedBlock, SentinelBlock, TimerEnum
from common.tpm_identity import create_identity
from integrations.factory import load_siem_integration


def canonical_payload(block: SealedBlock) -> bytes:
    return json.dumps(block.model_dump(mode="json"), sort_keys=True).encode("utf-8")


def load_registry() -> dict:
    try:
        return json.loads(Path(settings.SENTINEL_PUBLIC_KEY_REGISTRY_PATH).read_text())
    except Exception:
        return {}


def verify_admin_signature(body: dict) -> bool:
    action, ip, timestamp = body.get("action"), body.get("ip"), body.get("timestamp")
    signature = body.get("signature", "")
    message = json.dumps({"action": action, "ip": ip, "timestamp": timestamp}, sort_keys=True)
    expected = hmac.new(
        settings.CLUSTER_ADMIN_PASSWORD.encode(),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return bool(settings.CLUSTER_ADMIN_PASSWORD) and secrets.compare_digest(expected, signature)


class LedgerDatabase:
    def __init__(self, db_path: str = settings.LEDGER_DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS blocks (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                super_root TEXT NOT NULL,
                timer_enum INTEGER NOT NULL,
                micro_roots TEXT NOT NULL,
                signature TEXT NOT NULL,
                node_signatures TEXT NOT NULL DEFAULT '[]',
                confirmed INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            )
        """)
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_blocks_ts ON blocks (timestamp)")
        self.conn.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)")
        self.conn.commit()
        self.lock = threading.Lock()

    def set_meta(self, key: str, value: str):
        with self.lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
                (key, value),
            )
            self.conn.commit()

    def get_meta(self, key: str) -> Optional[str]:
        with self.lock:
            row = self.conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row[0] if row else None

    def insert_block(self, block: SentinelBlock):
        with self.lock:
            self.conn.execute(
                """
                INSERT OR IGNORE INTO blocks
                (id, timestamp, super_root, timer_enum, micro_roots, signature, node_signatures, confirmed, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    block.block_id,
                    block.payload.timestamp,
                    block.payload.super_root,
                    int(block.payload.timer_enum),
                    json.dumps(block.payload.micro_roots),
                    block.payload.signature,
                    json.dumps(block.node_signatures),
                    1 if block.confirmed else 0,
                    datetime.utcnow().isoformat(),
                ),
            )
            self.conn.commit()

    def get_block(self, block_id: str) -> Optional[SentinelBlock]:
        with self.lock:
            row = self.conn.execute(
                "SELECT * FROM blocks WHERE id = ?", (block_id,)
            ).fetchone()
        if not row:
            return None
        return self._row_to_block(row)

    def get_blocks_by_timeframe(self, start: str, end: str) -> List[SentinelBlock]:
        with self.lock:
            rows = self.conn.execute(
                "SELECT * FROM blocks WHERE timestamp >= ? AND timestamp <= ? ORDER BY timestamp ASC",
                (start, end),
            ).fetchall()
        return [self._row_to_block(r) for r in rows]

    def get_latest_block(self) -> Optional[SentinelBlock]:
        with self.lock:
            row = self.conn.execute(
                "SELECT * FROM blocks ORDER BY created_at DESC LIMIT 1"
            ).fetchone()
        if not row:
            return None
        return self._row_to_block(row)

    @staticmethod
    def _row_to_block(row) -> SentinelBlock:
        return SentinelBlock(
            block_id=row[0],
            payload=SealedBlock(
                super_root=row[2],
                timer_enum=TimerEnum(row[3]),
                micro_roots=json.loads(row[4]),
                signature=row[5],
                timestamp=row[1],
            ),
            node_signatures=json.loads(row[6]),
            confirmed=bool(row[7]),
        )


class CryptoVerifier:
    """Verifies Oracle blocks with the Oracle's public key (fail-closed)."""

    def __init__(self, public_key_pem: Optional[str] = None):
        self.public_key_pem = public_key_pem if public_key_pem is not None else self._load_default_key()

    @staticmethod
    def _load_default_key() -> str:
        try:
            return Path(settings.SENTINEL_ORACLE_PUBLIC_KEY_PATH).read_text()
        except (FileNotFoundError, OSError):
            return ""

    def verify(self, block: SealedBlock) -> bool:
        if not self.public_key_pem:
            return False
        try:
            return verify_signature(
                block.super_root.encode("utf-8"),
                bytes.fromhex(block.signature),
                self.public_key_pem,
            )
        except ValueError:
            return False


class ConsensusEngine:
    def __init__(self, node_ips: Optional[List[str]] = None, identity=None, registry: Optional[dict] = None):
        self.node_ips = list(node_ips or settings.SENTINEL_NODE_IPS)
        self.identity = identity
        self.registry = registry if registry is not None else load_registry()
        self.lock = threading.Lock()

    def add_peer(self, ip: str):
        with self.lock:
            if ip not in self.node_ips:
                self.node_ips.append(ip)

    def remove_peer(self, ip: str):
        with self.lock:
            self.node_ips = [i for i in self.node_ips if i != ip]

    def quorum(self) -> int:
        return len(self.node_ips) // 2 + 1

    def gossip_verify(self, block: SealedBlock, my_ip: str) -> List[str]:
        """Proof-of-Authority gossip: collect verified peer signatures."""
        payload = canonical_payload(block)
        signatures: List[str] = []
        if self.identity is not None:
            signatures.append(self.identity.sign_payload(payload).hex())

        for ip in self.node_ips:
            if ip == my_ip:
                continue
            try:
                resp = requests.post(
                    f"http://{ip}:{settings.SENTINEL_API_PORT}/verify",
                    data=json.dumps(block.model_dump(mode="json")),
                    headers={"Content-Type": "application/json"},
                    timeout=3,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    sig = data.get("signature", "")
                    if data.get("valid") and sig:
                        peer_pem = self.registry.get(ip)
                        if peer_pem and verify_signature(payload, bytes.fromhex(sig), peer_pem):
                            signatures.append(sig)
            except Exception:
                continue
        return signatures

    def broadcast_topology(self):
        payload = json.dumps({"topology": self.node_ips})
        for ip in self.node_ips:
            try:
                requests.post(
                    f"http://{ip}:{settings.SENTINEL_API_PORT}/admin/topology",
                    data=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=3,
                )
            except Exception:
                continue


class NodeAPI:
    def __init__(self, ledger: LedgerDatabase, verifier: CryptoVerifier, consensus: ConsensusEngine, my_ip: str, daemon: "SentinelDaemon"):
        self.app = FastAPI(title=f"Sentinel Node {my_ip}")
        self.ledger = ledger
        self.verifier = verifier
        self.consensus = consensus
        self.my_ip = my_ip
        self.daemon = daemon
        self._register_routes()

    def _register_routes(self):
        @self.app.post("/block")
        async def propose_block(request: Request):
            body = await request.json()
            block = SealedBlock(**body)

            if not self.verifier.verify(block):
                raise HTTPException(status_code=400, detail="Signature verification failed")

            node_sigs = self.consensus.gossip_verify(block, self.my_ip)
            block_id = sha256(block.super_root.encode("utf-8") + block.timestamp.encode("utf-8"))
            confirmed = len(node_sigs) >= self.consensus.quorum()

            sentinel_block = SentinelBlock(
                block_id=block_id,
                payload=block,
                node_signatures=node_sigs,
                confirmed=confirmed,
            )
            self.ledger.insert_block(sentinel_block)
            self.daemon.note_block()

            return {
                "status": "accepted" if confirmed else "pending",
                "block_id": block_id,
                "confirmations": len(node_sigs),
            }

        @self.app.post("/verify")
        async def verify_block(request: Request):
            body = await request.json()
            block = SealedBlock(**body)
            valid = self.verifier.verify(block)
            signature = ""
            if valid and self.consensus.identity is not None:
                signature = self.consensus.identity.sign_payload(canonical_payload(block)).hex()
            return {"valid": valid, "signature": signature}

        @self.app.post("/admin/add-node")
        async def admin_add_node(request: Request):
            body = await request.json()
            if not verify_admin_signature(body):
                raise HTTPException(status_code=403, detail="Unauthorized")
            ip = body.get("ip")
            if not ip:
                raise HTTPException(status_code=400, detail="Missing ip")
            self.consensus.add_peer(ip)
            self.ledger.set_meta("topology", json.dumps(self.consensus.node_ips))
            self.consensus.broadcast_topology()
            return {"status": "ok", "topology": self.consensus.node_ips, "quorum": self.consensus.quorum()}

        @self.app.post("/admin/evict")
        async def admin_evict_node(request: Request):
            body = await request.json()
            if not verify_admin_signature(body):
                raise HTTPException(status_code=403, detail="Unauthorized")
            ip = body.get("ip")
            if not ip:
                raise HTTPException(status_code=400, detail="Missing ip")
            self.consensus.remove_peer(ip)
            self.ledger.set_meta("topology", json.dumps(self.consensus.node_ips))
            self.consensus.broadcast_topology()
            return {"status": "ok", "topology": self.consensus.node_ips, "quorum": self.consensus.quorum()}

        @self.app.post("/admin/topology")
        async def sync_topology(request: Request):
            body = await request.json()
            topology = body.get("topology", [])
            self.consensus.node_ips = [ip for ip in topology if ip]
            self.ledger.set_meta("topology", json.dumps(self.consensus.node_ips))
            return {"status": "ok"}

        @self.app.get("/block/{block_id}")
        async def get_block(block_id: str):
            block = self.ledger.get_block(block_id)
            if not block:
                raise HTTPException(status_code=404, detail="Block not found")
            return block.model_dump()

        @self.app.get("/blocks")
        async def get_blocks(start: str = "", end: str = ""):
            if start and end:
                blocks = self.ledger.get_blocks_by_timeframe(start, end)
            else:
                latest = self.ledger.get_latest_block()
                blocks = [latest] if latest else []
            return [b.model_dump() for b in blocks]

        @self.app.get("/health")
        async def health():
            latest = self.ledger.get_latest_block()
            return {
                "status": "healthy",
                "latest_block": latest.block_id if latest else None,
                "latest_timestamp": latest.payload.timestamp if latest else None,
                "topology": self.consensus.node_ips,
                "quorum": self.consensus.quorum(),
            }


class DeadManSwitch:
    """Alerts (once per outage) when the Oracle stops delivering blocks."""

    def __init__(self, daemon: "SentinelDaemon"):
        self.daemon = daemon
        self._running = False
        self._alerted = False

    def start(self):
        self._running = True
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while self._running:
            age = time.time() - self.daemon.last_block_seen
            if age > settings.DEAD_MAN_SWITCH_THRESHOLD_SECONDS:
                if not self._alerted:
                    self._alerted = True
                    self._fire()
            else:
                self._alerted = False
            time.sleep(settings.DEAD_MAN_SWITCH_INTERVAL_SECONDS)

    def _fire(self):
        try:
            integration = load_siem_integration()
            integration.trigger_alert({
                "rule": {"id": "900002", "level": 12, "description": "Oracle heartbeat lost"},
                "data": {
                    "source": f"sentinel:{self.daemon.my_ip}",
                    "reported_by": getpass.getuser(),
                    "message": "No blocks received from the Oracle within the dead man switch threshold",
                },
            })
        except Exception:
            pass


def udp_discovery_responder(port: int = settings.UDP_DISCOVERY_PORT):
    """Reply to `CQ_DISCOVER` broadcasts so `cli/setup.py` can auto-detect peers."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("", port))
    except OSError:
        return
    sock.settimeout(1)
    while True:
        try:
            data, addr = sock.recvfrom(64)
            if data == b"CQ_DISCOVER":
                sock.sendto(b"CQ_SENTINEL", addr)
        except socket.timeout:
            continue
        except OSError:
            break


class SentinelDaemon:
    def __init__(self, my_ip: str = "127.0.0.1", identity_key_path: str = None):
        self.my_ip = my_ip
        self.last_block_seen = time.time()
        self.ledger = LedgerDatabase()
        self.identity = create_identity(
            kind=settings.IDENTITY_KIND,
            key_path=identity_key_path or settings.SENTINEL_IDENTITY_KEY_PATH,
            passphrase=settings.CLUSTER_PASSWORD or None,
        )
        self.verifier = CryptoVerifier()
        topology = self.ledger.get_meta("topology")
        node_ips = json.loads(topology) if topology else settings.SENTINEL_NODE_IPS
        self.consensus = ConsensusEngine(node_ips=node_ips, identity=self.identity, registry=load_registry())
        self.api = NodeAPI(self.ledger, self.verifier, self.consensus, self.my_ip, self)
        self.dead_man_switch = DeadManSwitch(self)

    def note_block(self):
        self.last_block_seen = time.time()

    def run(self):
        self.dead_man_switch.start()
        threading.Thread(target=udp_discovery_responder, daemon=True).start()
        uvicorn.run(self.api.app, host="0.0.0.0", port=settings.SENTINEL_API_PORT)


if __name__ == "__main__":
    my_ip = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    key_path = sys.argv[2] if len(sys.argv) > 2 else None
    daemon = SentinelDaemon(my_ip, key_path)
    daemon.run()
