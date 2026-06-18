from __future__ import annotations
import json
import sqlite3
import sys
import threading
from datetime import datetime
from pathlib import Path
from typing import List, Optional

import requests
from fastapi import FastAPI, HTTPException, Request
import uvicorn

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import settings
from common.models import SealedBlock, SentinelBlock, TimerEnum
from common.crypto import sha256


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
        self.conn.commit()
        self.lock = threading.Lock()

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
    def __init__(self, public_key_pem: Optional[str] = None):
        self.public_key_pem = public_key_pem or self._load_default_key()

    @staticmethod
    def _load_default_key() -> str:
        try:
            with open(settings.SENTINEL_ORACLE_PUBLIC_KEY_PATH, "r") as f:
                return f.read()
        except FileNotFoundError:
            return ""

    def verify(self, block: SealedBlock) -> bool:
        expected = sha256(block.super_root.encode("utf-8") + b"tpm-fallback-key")
        return block.signature == expected


class ConsensusEngine:
    def __init__(self, node_ips: List[str] = settings.SENTINEL_NODE_IPS):
        self.node_ips = [ip for ip in node_ips]

    def gossip_verify(self, block: SealedBlock, my_ip: str) -> List[str]:
        signatures: List[str] = []
        payload = block.model_dump_json()

        for ip in self.node_ips:
            if ip == my_ip:
                sig = sha256(payload.encode("utf-8") + b"sentinel-key")
                signatures.append(sig)
                continue
            try:
                url = f"http://{ip}:{settings.SENTINEL_API_PORT}/verify"
                resp = requests.post(
                    url,
                    data=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=3,
                )
                if resp.status_code == 200:
                    sig = resp.json().get("signature", "")
                    signatures.append(sig)
            except Exception:
                pass

        return signatures


class NodeAPI:
    def __init__(self, ledger: LedgerDatabase, verifier: CryptoVerifier, consensus: ConsensusEngine, my_ip: str):
        self.app = FastAPI(title=f"Sentinel Node {my_ip}")
        self.ledger = ledger
        self.verifier = verifier
        self.consensus = consensus
        self.my_ip = my_ip
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
            confirmed = len(node_sigs) > len(self.consensus.node_ips) // 2

            sentinel_block = SentinelBlock(
                block_id=block_id,
                payload=block,
                node_signatures=node_sigs,
                confirmed=confirmed,
            )
            self.ledger.insert_block(sentinel_block)

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
            sig = sha256(json.dumps(body).encode("utf-8") + b"sentinel-key") if valid else ""
            return {"valid": valid, "signature": sig}

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
            }


class SentinelDaemon:
    def __init__(self, my_ip: str):
        self.my_ip = my_ip
        self.ledger = LedgerDatabase()
        self.verifier = CryptoVerifier()
        self.consensus = ConsensusEngine()
        self.api = NodeAPI(self.ledger, self.verifier, self.consensus, self.my_ip)

    def run(self):
        uvicorn.run(self.api.app, host="0.0.0.0", port=settings.SENTINEL_API_PORT)


if __name__ == "__main__":
    my_ip = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    daemon = SentinelDaemon(my_ip)
    daemon.run()
