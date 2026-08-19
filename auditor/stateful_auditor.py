from __future__ import annotations
import getpass
import logging
import random
import sys
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import settings
from common.crypto import bucket_size_for, build_micro_roots, build_super_root, parse_timestamp
from common.models import AuditReport, LogEntry, SentinelBlock, SIEMQueryRange
from integrations.base_siem import SIEMIntegration
from integrations.factory import load_siem_integration

logger = logging.getLogger("cyberqalxan.auditor")


class ThreeTierScheduler:
    """Vanguard (1-min), 24h sweep, and 30d random spot-checks."""

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
    def __init__(self, integration: SIEMIntegration):
        self.integration = integration

    def pull_logs(self, start_time: str, end_time: str) -> Optional[List[LogEntry]]:
        return self.integration.fetch_historical_logs(start_time, end_time)


class LedgerReader:
    def __init__(self, node_ips: List[str] = settings.SENTINEL_NODE_IPS):
        self.node_ips = node_ips

    def fetch_blocks_by_timeframe(self, start: str, end: str) -> List[SentinelBlock]:
        for node in random.sample(self.node_ips, min(3, len(self.node_ips))):
            try:
                resp = requests.get(
                    f"http://{node}:{settings.SENTINEL_API_PORT}/blocks",
                    params={"start": start, "end": end},
                    timeout=5,
                )
                if resp.status_code == 200:
                    return [SentinelBlock(**b) for b in resp.json()]
            except Exception:
                continue
        return []


class VerificationEngine:
    @staticmethod
    def verify(siem_logs: List[LogEntry], ledger_block: SentinelBlock):
        """Rebuild the Oracle's micro-roots for the block's minute and compare.

        Returns (passed, tampered_window_labels).
        """
        timer_enum = ledger_block.payload.timer_enum
        stored = ledger_block.payload.micro_roots
        recovered = build_micro_roots(siem_logs, timer_enum)

        mismatched: List[int] = []
        for i in range(min(len(recovered), len(stored))):
            if recovered[i] != stored[i]:
                mismatched.append(i)
        if len(recovered) != len(stored):
            mismatched.extend(range(min(len(recovered), len(stored)), max(len(recovered), len(stored))))

        recovered_super = build_super_root(recovered)
        passed = recovered_super == ledger_block.payload.super_root and not mismatched
        windows = VerificationEngine._window_labels(ledger_block, sorted(set(mismatched)))
        return passed, windows

    @staticmethod
    def _window_labels(block: SentinelBlock, indices: List[int]) -> List[str]:
        start = parse_timestamp(block.payload.timestamp)
        if start is None:
            return [f"bucket_{i}" for i in indices]
        size = bucket_size_for(block.payload.timer_enum)
        labels = []
        for i in indices:
            ws = start + timedelta(seconds=i * size)
            we = ws + timedelta(seconds=size)
            labels.append(f"{ws:%Y-%m-%dT%H:%M:%S} - {we:%Y-%m-%dT%H:%M:%S}")
        return labels


class AlertManager:
    def __init__(self, integration: SIEMIntegration, username: Optional[str] = None):
        self.integration = integration
        self.username = username or getpass.getuser()

    def trigger(self, report: AuditReport):
        doc = {
            "rule": {
                "id": "900001",
                "level": 12,
                "description": "Log integrity violation detected by CyberQalxan",
            },
            "data": {
                "timeframe_start": report.timeframe.start_time,
                "timeframe_end": report.timeframe.end_time,
                "tampered_windows": report.mismatched_windows,
                "recovered_root": report.recovered_root or "",
                "stored_root": report.stored_root or "",
                "reported_by": self.username,
            },
        }
        self.integration.trigger_alert(doc)
        try:
            requests.post(
                settings.ALERT_WEBHOOK_URL,
                json={
                    "labels": {"alert": "cyberqalxan_integrity_failure"},
                    "annotations": {
                        "summary": "Log integrity violation detected",
                        "timeframe": report.timeframe.model_dump_json(),
                        "tampered_windows": ",".join(report.mismatched_windows),
                        "reported_by": self.username,
                    },
                },
                headers={"Content-Type": "application/json"},
                timeout=5,
            )
        except Exception:
            pass


class AuditDaemon:
    def __init__(self):
        self.integration = load_siem_integration()
        self.scheduler = ThreeTierScheduler()
        self.siem_puller = SIEM_Puller(self.integration)
        self.ledger_reader = LedgerReader()
        self.verifier = VerificationEngine()
        self.alert_manager = AlertManager(self.integration)
        self._lock = threading.Lock()
        self._inflight: Set[str] = set()
        self._alerted: Dict[str, float] = {}

    def _claim_block(self, block_id: str) -> bool:
        with self._lock:
            now = time.time()
            stale = [bid for bid, ts in self._alerted.items()
                     if now - ts > settings.AUDITOR_ALERT_DEDUP_WINDOW_SECONDS]
            for bid in stale:
                del self._alerted[bid]
            if block_id in self._alerted or block_id in self._inflight:
                return False
            self._inflight.add(block_id)
            return True

    def _finish_block(self, block_id: str, alerted: bool):
        with self._lock:
            self._inflight.discard(block_id)
            if alerted:
                self._alerted[block_id] = time.time()

    @staticmethod
    def _filter_logs_for_block(logs: List[LogEntry], block: SentinelBlock) -> List[LogEntry]:
        start = parse_timestamp(block.payload.timestamp)
        if start is None:
            return []
        end = start + timedelta(minutes=1)
        filtered = []
        for log in logs:
            ts = parse_timestamp(log.timestamp)
            if ts is None:
                continue
            if start <= ts < end:
                filtered.append(log)
        return filtered

    def _audit_window(self, start: str, end: str):
        logs = self.siem_puller.pull_logs(start, end)
        if logs is None:
            logger.warning("SIEM unreachable for %s..%s; skipping audit (no false alarm)", start, end)
            return

        blocks = self.ledger_reader.fetch_blocks_by_timeframe(start, end)
        for block in blocks:
            if not self._claim_block(block.block_id):
                continue
            alerted = False
            try:
                block_logs = self._filter_logs_for_block(logs, block)
                passed, windows = self.verifier.verify(block_logs, block)
                if not passed:
                    recovered_root = (
                        build_super_root(build_micro_roots(block_logs, block.payload.timer_enum))
                        if block_logs else None
                    )
                    report = AuditReport(
                        timeframe=SIEMQueryRange(start_time=start, end_time=end),
                        passed=False,
                        mismatched_windows=windows,
                        recovered_root=recovered_root,
                        stored_root=block.payload.super_root,
                    )
                    self.alert_manager.trigger(report)
                    alerted = True
            finally:
                self._finish_block(block.block_id, alerted)

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
