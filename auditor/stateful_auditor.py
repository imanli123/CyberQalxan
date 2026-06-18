from __future__ import annotations
import json
import random
import sys
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional, Tuple

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import settings
from common.models import AuditReport, SentinelBlock, SIEMQueryRange
from common.crypto import compute_micro_roots, compute_super_root


class ThreeTierScheduler:
    def __init__(self, max_concurrent: int = settings.AUDITOR_MAX_CONCURRENT_THREADS):
        self.semaphore = threading.Semaphore(max_concurrent)
        self._running = False

    def start(self, vanguard_cb, sweep_24h_cb, spot_check_30d_cb):
        self._running = True
        threads = [
            threading.Thread(target=self._run_vanguard, args=(vanguard_cb,), daemon=True),
            threading.Thread(target=self._run_24h_sweep, args=(sweep_24h_cb,), daemon=True),
            threading.Thread(target=self._run_30d_spot, args=(spot_check_30d_cb,), daemon=True),
        ]
        for t in threads:
            t.start()

    def stop(self):
        self._running = False

    def _run_vanguard(self, cb):
        while self._running:
            now = datetime.utcnow()
            target = now - timedelta(seconds=settings.AUDITOR_VANGUARD_DELAY_SECONDS + 60)
            end = now - timedelta(seconds=settings.AUDITOR_VANGUARD_DELAY_SECONDS)
            with self.semaphore:
                cb(target.isoformat(), end.isoformat())
            time.sleep(60)

    def _run_24h_sweep(self, cb):
        while self._running:
            now = datetime.utcnow()
            start = now - timedelta(hours=24, minutes=1)
            end = now - timedelta(hours=24)
            with self.semaphore:
                cb(start.isoformat(), end.isoformat())
            time.sleep(settings.AUDITOR_24H_SWEEP_INTERVAL_SECONDS)

    def _run_30d_spot(self, cb):
        while self._running:
            now = datetime.utcnow()
            offset_days = random.randint(1, 30)
            start = now - timedelta(days=offset_days, minutes=1)
            end = now - timedelta(days=offset_days)
            with self.semaphore:
                cb(start.isoformat(), end.isoformat())
            time.sleep(settings.AUDITOR_30D_CHECK_INTERVAL_SECONDS)


class SIEM_Puller:
    def __init__(
        self,
        base_url: str = settings.SIEM_API_BASE_URL,
        username: str = settings.SIEM_API_USERNAME,
        password: str = settings.SIEM_API_PASSWORD,
    ):
        self.base_url = base_url
        self.auth = (username, password)

    def pull_logs(self, start_time: str, end_time: str) -> List[str]:
        try:
            resp = requests.get(
                f"{self.base_url}/api/v1/alerts",
                params={
                    "start_time": start_time,
                    "end_time": end_time,
                    "limit": 10000,
                },
                auth=self.auth,
                timeout=30,
            )
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list):
                    return [json.dumps(item) for item in data]
                hits = data.get("hits", {}).get("hits", []) if isinstance(data, dict) else []
                return [json.dumps(h["_source"]) for h in hits]
        except Exception:
            pass
        return []


class LedgerReader:
    def __init__(self, node_ips: List[str] = settings.SENTINEL_NODE_IPS):
        self.node_ips = node_ips

    def fetch_block(self, block_id: str) -> Optional[SentinelBlock]:
        node = random.choice(self.node_ips)
        try:
            resp = requests.get(
                f"http://{node}:{settings.SENTINEL_API_PORT}/block/{block_id}",
                timeout=5,
            )
            if resp.status_code == 200:
                return SentinelBlock(**resp.json())
        except Exception:
            pass
        return None

    def fetch_blocks_by_timeframe(self, start: str, end: str) -> List[SentinelBlock]:
        node = random.choice(self.node_ips)
        try:
            resp = requests.get(
                f"http://{node}:{settings.SENTINEL_API_PORT}/blocks",
                params={"start": start, "end": end},
                timeout=5,
            )
            if resp.status_code == 200:
                return [SentinelBlock(**b) for b in resp.json()]
        except Exception:
            pass
        return []


class VerificationEngine:
    @staticmethod
    def verify(siem_logs: List[str], ledger_block: SentinelBlock) -> Tuple[bool, List[str]]:
        micro_root_count = len(ledger_block.payload.micro_roots)

        if not siem_logs:
            return False, ["no-siem-logs"]

        chunk_size = max(1, len(siem_logs) // max(micro_root_count, 1))
        buckets = [
            siem_logs[i : i + chunk_size]
            for i in range(0, len(siem_logs), chunk_size)
        ]

        recovered_micro_roots = compute_micro_roots(buckets)
        mismatched: List[str] = []

        for i in range(min(len(recovered_micro_roots), len(ledger_block.payload.micro_roots))):
            if recovered_micro_roots[i] != ledger_block.payload.micro_roots[i]:
                mismatched.append(f"micro_root_{i}")

        recovered_super_root = compute_super_root(recovered_micro_roots)
        passed = (
            recovered_super_root == ledger_block.payload.super_root
            and not mismatched
        )

        return passed, mismatched


class AlertManager:
    @staticmethod
    def trigger(report: AuditReport):
        payload = {
            "labels": {"alert": "cyberqalxan_integrity_failure"},
            "annotations": {
                "summary": "Log integrity violation detected",
                "timeframe": report.timeframe.model_dump_json(),
                "mismatched_windows": ",".join(report.mismatched_windows),
                "recovered_root": report.recovered_root or "",
                "stored_root": report.stored_root or "",
            },
        }
        try:
            requests.post(
                settings.ALERT_WEBHOOK_URL,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=5,
            )
        except Exception:
            pass


class AuditDaemon:
    def __init__(self):
        self.scheduler = ThreeTierScheduler()
        self.siem_puller = SIEM_Puller()
        self.ledger_reader = LedgerReader()
        self.verifier = VerificationEngine()
        self.alert_manager = AlertManager()

    def _audit_window(self, start: str, end: str):
        siem_logs = self.siem_puller.pull_logs(start, end)
        ledger_blocks = self.ledger_reader.fetch_blocks_by_timeframe(start, end)

        if not ledger_blocks:
            return

        for block in ledger_blocks:
            passed, mismatched = self.verifier.verify(siem_logs, block)
            report = AuditReport(
                timeframe=SIEMQueryRange(start_time=start, end_time=end),
                passed=passed,
                mismatched_windows=mismatched,
                recovered_root=compute_super_root(
                    compute_micro_roots([siem_logs])
                ) if siem_logs else None,
                stored_root=block.payload.super_root,
            )
            if not passed:
                self.alert_manager.trigger(report)

    def run(self):
        self.scheduler.start(
            vanguard_cb=self._audit_window,
            sweep_24h_cb=self._audit_window,
            spot_check_30d_cb=self._audit_window,
        )
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.scheduler.stop()


if __name__ == "__main__":
    daemon = AuditDaemon()
    daemon.run()
