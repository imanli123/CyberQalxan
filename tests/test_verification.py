from __future__ import annotations
import unittest

from common.crypto import build_micro_roots, build_super_root
from common.models import LogEntry, SealedBlock, SentinelBlock, TimerEnum
from auditor.stateful_auditor import VerificationEngine


def log(second: int, raw: str) -> LogEntry:
    return LogEntry(raw=raw, timestamp=f"2026-08-18T12:05:{second:02d}.000000")


def make_block(logs, timer_enum=TimerEnum.MODERATE_10S) -> SentinelBlock:
    micro_roots = build_micro_roots(logs, timer_enum)
    payload = SealedBlock(
        super_root=build_super_root(micro_roots),
        timer_enum=timer_enum,
        micro_roots=micro_roots,
        signature="deadbeef",
        timestamp="2026-08-18T12:05:00",
    )
    return SentinelBlock(block_id="b1", payload=payload, node_signatures=[], confirmed=True)


class TestVerification(unittest.TestCase):
    def test_pristine_logs_pass(self):
        logs = [log(s, f"event-{s}") for s in range(60)]
        block = make_block(logs)
        passed, windows = VerificationEngine.verify(logs, block)
        self.assertTrue(passed)
        self.assertEqual(windows, [])

    def test_tampered_log_detected_with_window(self):
        logs = [log(s, f"event-{s}") for s in range(60)]
        block = make_block(logs)
        tampered = list(logs)
        tampered[7] = log(7, "EVENT-TAMPERED")
        passed, windows = VerificationEngine.verify(tampered, block)
        self.assertFalse(passed)
        # log at second 7 -> bucket index 0 for a 10s timer
        self.assertEqual(windows, ["2026-08-18T12:05:00 - 2026-08-18T12:05:10"])

    def test_deleted_logs_detected(self):
        logs = [log(s, f"event-{s}") for s in range(60)]
        block = make_block(logs)
        tampered = [l for l in logs if l.raw != "event-30"]
        passed, windows = VerificationEngine.verify(tampered, block)
        self.assertFalse(passed)
        self.assertTrue(any("12:05:30" in w for w in windows))

    def test_inserted_log_detected(self):
        logs = [log(s, f"event-{s}") for s in range(60)]
        block = make_block(logs)
        tampered = list(logs) + [log(45, "injected-event")]
        passed, windows = VerificationEngine.verify(tampered, block)
        self.assertFalse(passed)

    def test_different_timer_enum_reproducible(self):
        logs = [log(s, f"event-{s}") for s in range(60)]
        block = make_block(logs, timer_enum=TimerEnum.AGGRESSIVE_5S)
        passed, _ = VerificationEngine.verify(logs, block)
        self.assertTrue(passed)


if __name__ == "__main__":
    unittest.main()