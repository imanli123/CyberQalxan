from __future__ import annotations
import json
import sys
import time
import threading
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np
import requests
from fastapi import FastAPI, Request
from sklearn.ensemble import IsolationForest
import uvicorn

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import settings
from common.models import LogEntry, MerkleBatch, SealedBlock, TimerEnum
from common.crypto import compute_micro_roots, compute_super_root, sha256


class WebhookListener:
    def __init__(self, buffer: RAM_Buffer):
        self.app = FastAPI(title="Oracle Ingestion")
        self.buffer = buffer
        self._register_routes()

    def _register_routes(self):
        @self.app.post("/webhook")
        async def ingest(request: Request):
            body = await request.json()
            if isinstance(body, list):
                for entry in body:
                    log = LogEntry(
                        raw=json.dumps(entry),
                        timestamp=entry.get("timestamp", datetime.utcnow().isoformat()),
                    )
                    self.buffer.add_log(log)
            elif isinstance(body, dict):
                log = LogEntry(
                    raw=json.dumps(body),
                    timestamp=body.get("timestamp", datetime.utcnow().isoformat()),
                )
                self.buffer.add_log(log)
            return {"status": "ingested"}

    def run(self, host: str = settings.ORACLE_HOST, port: int = settings.ORACLE_PORT):
        uvicorn.run(self.app, host=host, port=port)


class RAM_Buffer:
    def __init__(self, max_mb: int = settings.RAM_BUFFER_MAX_MB):
        self.max_bytes = max_mb * 1024 * 1024
        self.buckets: Dict[str, List[LogEntry]] = defaultdict(list)
        self.lock = threading.Lock()

    def add_log(self, log: LogEntry):
        with self.lock:
            minute_key = log.timestamp[:16]
            self.buckets[minute_key].append(log)

    def estimate_size_bytes(self) -> int:
        total = 0
        with self.lock:
            for entries in self.buckets.values():
                for e in entries:
                    total += len(e.raw.encode("utf-8")) + len(e.timestamp.encode("utf-8"))
        return total

    def flush_bucket(self, minute_key: str) -> List[LogEntry]:
        with self.lock:
            return self.buckets.pop(minute_key, [])

    def get_ready_minutes(self, cutoff_dt: datetime, grace: int = settings.RAM_BUFFER_GRACE_SECONDS) -> List[str]:
        ready: List[str] = []
        cutoff_str = (cutoff_dt - timedelta(seconds=grace)).strftime("%Y-%m-%dT%H:%M")
        with self.lock:
            for key in list(self.buckets.keys()):
                if key < cutoff_str:
                    ready.append(key)
        return sorted(ready)


class AI_ThreatEngine:
    def __init__(self):
        self.model = IsolationForest(contamination=0.1, random_state=42)
        self.velocity_history: List[float] = []
        self.trained = False

    def analyze_velocity(self, recent_buckets: Dict[str, List[LogEntry]]) -> TimerEnum:
        velocities = []
        for key in sorted(recent_buckets.keys()):
            velocities.append(float(len(recent_buckets[key])))

        self.velocity_history.extend(velocities)
        window = self.velocity_history[-50:]
        if len(window) < 10:
            return TimerEnum.STANDARD_60S

        X = np.array(window).reshape(-1, 1)
        if not self.trained:
            self.model.fit(X)
            self.trained = True
        else:
            self.model.fit(X)

        preds = self.model.predict(X)
        anomaly_ratio = float((preds == -1).sum()) / len(preds)

        if anomaly_ratio > 0.3:
            return TimerEnum.AGGRESSIVE_5S
        elif anomaly_ratio > 0.1:
            return TimerEnum.MODERATE_10S
        return TimerEnum.STANDARD_60S


class MerkleRollupEngine:
    @staticmethod
    def rollup_buckets(buckets: Dict[str, List[LogEntry]]) -> MerkleBatch:
        all_logs: List[List[str]] = []
        for key in sorted(buckets.keys()):
            group = [log.raw for log in buckets[key]]
            all_logs.append(group)

        micro_roots = compute_micro_roots(all_logs)
        super_root = compute_super_root(micro_roots)
        return MerkleBatch(micro_roots=micro_roots, super_root=super_root)


class TPM_HardwareSigner:
    def __init__(self, device_path: str = settings.TPM_DEVICE_PATH):
        self.device_path = device_path
        self.public_key: Optional[str] = None

    def sign(self, super_root: str) -> str:
        data = super_root.encode("utf-8")
        try:
            with open(self.device_path, "rb") as tpm:
                tpm.write(data)
                signature = tpm.read(256)
            return signature.hex()
        except (FileNotFoundError, PermissionError, OSError):
            return sha256(data + b"tpm-fallback-key")


class Broadcaster:
    @staticmethod
    def broadcast(block: SealedBlock, targets: List[str]) -> List[bool]:
        results: List[bool] = []
        payload = block.model_dump_json()
        for target in targets:
            try:
                url = f"http://{target}:{settings.SENTINEL_API_PORT}/block"
                resp = requests.post(url, data=payload, headers={"Content-Type": "application/json"}, timeout=5)
                results.append(resp.status_code == 200)
            except Exception:
                results.append(False)
        return results


class OracleDaemon:
    def __init__(self):
        self.buffer = RAM_Buffer()
        self.listener = WebhookListener(self.buffer)
        self.threat_engine = AI_ThreatEngine()
        self.merkle_engine = MerkleRollupEngine()
        self.signer = TPM_HardwareSigner()
        self.broadcaster = Broadcaster()
        self._running = False

    def _engine_loop(self):
        while self._running:
            try:
                now = datetime.utcnow()
                ready = self.buffer.get_ready_minutes(now)
                timer_enum = TimerEnum.STANDARD_60S

                if ready:
                    buckets_data: Dict[str, List[LogEntry]] = {}
                    for minute_key in ready:
                        buckets_data[minute_key] = self.buffer.flush_bucket(minute_key)

                    timer_enum = self.threat_engine.analyze_velocity(buckets_data)
                    batch = self.merkle_engine.rollup_buckets(buckets_data)
                    signature = self.signer.sign(batch.super_root)

                    block = SealedBlock(
                        super_root=batch.super_root,
                        timer_enum=timer_enum,
                        micro_roots=batch.micro_roots,
                        signature=signature,
                        timestamp=now.isoformat(),
                    )

                    self.broadcaster.broadcast(block, settings.SENTINEL_NODE_IPS)

                sleep_map = {TimerEnum.AGGRESSIVE_5S: 5, TimerEnum.MODERATE_10S: 10, TimerEnum.STANDARD_60S: 60}
                time.sleep(sleep_map.get(timer_enum, 60))

            except Exception:
                time.sleep(10)

    def run(self):
        self._running = True
        engine_thread = threading.Thread(target=self._engine_loop, daemon=True)
        engine_thread.start()
        self.listener.run()


if __name__ == "__main__":
    daemon = OracleDaemon()
    daemon.run()
