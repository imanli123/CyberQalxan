from __future__ import annotations
import sys
import threading
import time
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List

import numpy as np
import uvicorn
from fastapi import FastAPI, HTTPException, Request
from sklearn.ensemble import IsolationForest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import settings
from common.crypto import build_micro_roots, build_super_root
from common.models import LogEntry, MerkleBatch, SealedBlock, TimerEnum
from common.tpm_identity import create_identity
from integrations.factory import load_siem_integration


class WebhookListener:
    def __init__(self, buffer: "RAM_Buffer", integration, signer: "BlockSigner"):
        self.app = FastAPI(title="Oracle Ingestion")
        self.buffer = buffer
        self.integration = integration
        self.signer = signer
        self._register_routes()

    def _register_routes(self):
        @self.app.post("/webhook")
        async def ingest(request: Request):
            if not self.integration.verify_webhook(request):
                raise HTTPException(status_code=401, detail="Unauthorized")
            body = await request.json()
            for log in self.integration.parse_payload(body):
                self.buffer.add_log(log)
            return {"status": "ingested", "logs": self.buffer.total_logs()}

        @self.app.get("/public_key")
        async def get_public_key(request: Request):
            provided = request.headers.get("X-Cluster-Admin-Password", "")
            if not settings.CLUSTER_ADMIN_PASSWORD or provided != settings.CLUSTER_ADMIN_PASSWORD:
                raise HTTPException(status_code=401, detail="Unauthorized")
            return {"public_key": self.signer.get_public_key_pem()}

    def run(self, host: str = settings.ORACLE_HOST, port: int = settings.ORACLE_PORT):
        uvicorn.run(self.app, host=host, port=port)


class RAM_Buffer:
    def __init__(self, max_mb: int = settings.RAM_BUFFER_MAX_MB):
        self.max_bytes = max_mb * 1024 * 1024
        self.buckets: Dict[str, List[LogEntry]] = defaultdict(list)
        self.lock = threading.Lock()
        self.overflow_dropped = 0
        self._warned = False

    def add_log(self, log: LogEntry):
        with self.lock:
            minute_key = log.timestamp[:16]
            self.buckets[minute_key].append(log)
            if self._estimate_unlocked() > self.max_bytes:
                self.buckets[minute_key].pop()
                self.overflow_dropped += 1
                if not self._warned:
                    self._warned = True
                    print("[RAM_Buffer] WARNING: memory limit exceeded; dropping incoming logs")

    def _estimate_unlocked(self) -> int:
        total = 0
        for entries in self.buckets.values():
            for e in entries:
                total += len(e.raw.encode("utf-8")) + len(e.timestamp.encode("utf-8"))
        return total

    def estimate_size_bytes(self) -> int:
        with self.lock:
            return self._estimate_unlocked()

    def total_logs(self) -> int:
        with self.lock:
            return sum(len(v) for v in self.buckets.values())

    def flush_bucket(self, minute_key: str) -> List[LogEntry]:
        with self.lock:
            return self.buckets.pop(minute_key, [])

    def get_ready_minutes(self, cutoff_dt: datetime, grace: int = settings.RAM_BUFFER_GRACE_SECONDS) -> List[str]:
        """Minutes whose window (minute start + 60s) has fully passed the grace cutoff."""
        cutoff = cutoff_dt - timedelta(seconds=grace)
        ready: List[str] = []
        with self.lock:
            for key in list(self.buckets.keys()):
                try:
                    minute_start = datetime.strptime(key + ":00", "%Y-%m-%dT%H:%M:%S")
                except ValueError:
                    continue
                if minute_start + timedelta(minutes=1) <= cutoff:
                    ready.append(key)
        return sorted(ready)

    def get_minute_counts(self, window_minutes: int = settings.AI_THREAT_ENGINE_WINDOW_MINUTES) -> Dict[str, int]:
        with self.lock:
            return {key: len(entries) for key, entries in self.buckets.items()}


class AI_ThreatEngine:
    """Determines how tightly the buffer should slice data based on log velocity."""

    def __init__(self):
        self.model = IsolationForest(contamination=0.1, random_state=42)
        self.velocity_history: List[float] = []
        self.trained = False

    def analyze_velocity(self, minute_counts: Dict[str, int]) -> TimerEnum:
        velocities = [float(v) for v in minute_counts.values()]
        self.velocity_history.extend(velocities)
        window = self.velocity_history[-50:]
        if len(window) < 10:
            return TimerEnum.STANDARD_60S

        x = np.array(window).reshape(-1, 1)
        self.model.fit(x)
        self.trained = True
        predictions = self.model.predict(x)
        anomaly_ratio = float((predictions == -1).sum()) / len(predictions)

        if anomaly_ratio > 0.3:
            return TimerEnum.AGGRESSIVE_5S
        if anomaly_ratio > 0.1:
            return TimerEnum.MODERATE_10S
        return TimerEnum.STANDARD_60S


class MerkleRollupEngine:
    @staticmethod
    def rollup_minute(minute_key: str, logs: List[LogEntry], timer_enum: TimerEnum) -> MerkleBatch:
        """Roll a single minute of logs into micro-roots + super-root."""
        micro_roots = build_micro_roots(logs, timer_enum)
        super_root = build_super_root(micro_roots)
        return MerkleBatch(micro_roots=micro_roots, super_root=super_root)


class BlockSigner:
    """Wraps a NodeIdentity/TPM identity to sign super-roots."""

    def __init__(self, identity):
        self.identity = identity

    def sign(self, super_root: str) -> str:
        return self.identity.sign_payload(super_root.encode("utf-8")).hex()

    def get_public_key_pem(self) -> str:
        return self.identity.get_public_key_pem()


class Broadcaster:
    @staticmethod
    def broadcast(block: SealedBlock, targets: List[str]) -> List[bool]:
        import requests

        results: List[bool] = []
        payload = block.model_dump_json()
        for target in targets:
            try:
                url = f"http://{target}:{settings.SENTINEL_API_PORT}/block"
                resp = requests.post(
                    url,
                    data=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=5,
                )
                results.append(resp.status_code == 200)
            except Exception:
                results.append(False)
        return results


class OracleDaemon:
    def __init__(self):
        self.integration = load_siem_integration()
        self.buffer = RAM_Buffer()
        self.identity = create_identity(
            kind=settings.IDENTITY_KIND,
            key_path=settings.ORACLE_IDENTITY_KEY_PATH,
            passphrase=settings.CLUSTER_PASSWORD or None,
        )
        self.identity.save_public_key(settings.ORACLE_PUBLIC_KEY_PATH)
        self.signer = BlockSigner(self.identity)
        self.listener = WebhookListener(self.buffer, self.integration, self.signer)
        self.threat_engine = AI_ThreatEngine()
        self.merkle_engine = MerkleRollupEngine()
        self.broadcaster = Broadcaster()
        self._running = False

    def _engine_loop(self):
        while self._running:
            try:
                now = datetime.utcnow()
                ready = self.buffer.get_ready_minutes(now)
                if ready:
                    minute_counts = self.buffer.get_minute_counts(settings.AI_THREAT_ENGINE_WINDOW_MINUTES)
                    timer_enum = self.threat_engine.analyze_velocity(minute_counts)
                    for minute_key in ready:
                        logs = self.buffer.flush_bucket(minute_key)
                        if not logs:
                            continue
                        batch = self.merkle_engine.rollup_minute(minute_key, logs, timer_enum)
                        signature = self.signer.sign(batch.super_root)
                        block = SealedBlock(
                            super_root=batch.super_root,
                            timer_enum=timer_enum,
                            micro_roots=batch.micro_roots,
                            signature=signature,
                            timestamp=f"{minute_key}:00",
                        )
                        self.broadcaster.broadcast(block, settings.SENTINEL_NODE_IPS)
                time.sleep(5)
            except Exception as exc:
                print(f"[Oracle] engine loop error: {exc!r}")
                time.sleep(10)

    def run(self):
        self._running = True
        engine_thread = threading.Thread(target=self._engine_loop, daemon=True)
        engine_thread.start()
        self.listener.run()


if __name__ == "__main__":
    daemon = OracleDaemon()
    daemon.run()
