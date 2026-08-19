from __future__ import annotations
import unittest

from common.crypto import (
    EMPTY_BUCKET_PLACEHOLDER,
    build_micro_roots,
    build_super_root,
    bucket_size_for,
    hash_log,
    micro_root_for_bucket,
    sha256,
    slice_logs_into_buckets,
)
from common.models import LogEntry, TimerEnum


def log(second: int, micro: int = 0, raw: str = "test-event") -> LogEntry:
    return LogEntry(raw=raw, timestamp=f"2026-08-18T12:05:{second:02d}.{micro:06d}")


class TestMerkle(unittest.TestCase):
    def test_sha256_is_64_hex(self):
        self.assertEqual(len(sha256(b"x")), 64)

    def test_hash_log_deterministic(self):
        self.assertEqual(hash_log("a"), hash_log("a"))
        self.assertNotEqual(hash_log("a"), hash_log("b"))

    def test_single_bucket_super_root_is_micro_root(self):
        leaves = [log(1), log(2)]
        micro = micro_root_for_bucket(leaves)
        self.assertEqual(build_super_root([micro]), micro)

    def test_empty_bucket_placeholder_deterministic(self):
        a = micro_root_for_bucket([])
        b = micro_root_for_bucket([])
        self.assertEqual(a, b)
        self.assertEqual(a, sha256(EMPTY_BUCKET_PLACEHOLDER.encode("utf-8")))

    def test_bucket_sizes(self):
        self.assertEqual(bucket_size_for(TimerEnum.STANDARD_60S), 60)
        self.assertEqual(bucket_size_for(TimerEnum.AGGRESSIVE_5S), 5)
        self.assertEqual(bucket_size_for(TimerEnum.MODERATE_10S), 10)
        self.assertEqual(bucket_size_for(TimerEnum.MODERATE_15S), 15)
        self.assertEqual(bucket_size_for(TimerEnum.MODERATE_30S), 30)

    def test_slice_5s_gives_12_buckets(self):
        logs = [log(s) for s in range(60)]
        buckets = slice_logs_into_buckets(logs, TimerEnum.AGGRESSIVE_5S)
        self.assertEqual(len(buckets), 12)
        self.assertEqual([len(b) for b in buckets], [5] * 12)

    def test_slice_60s_gives_1_bucket(self):
        logs = [log(s) for s in range(60)]
        buckets = slice_logs_into_buckets(logs, TimerEnum.STANDARD_60S)
        self.assertEqual(len(buckets), 1)
        self.assertEqual(len(buckets[0]), 60)

    def test_slice_30s_gives_2_buckets(self):
        logs = [log(s) for s in range(60)]
        buckets = slice_logs_into_buckets(logs, TimerEnum.MODERATE_30S)
        self.assertEqual(len(buckets), 2)
        self.assertEqual([len(b) for b in buckets], [30, 30])

    def test_malformed_timestamp_dropped_not_crashed(self):
        bad = LogEntry(raw="x", timestamp="not-a-timestamp")
        roots = build_micro_roots([bad], TimerEnum.STANDARD_60S)
        self.assertEqual(roots, [micro_root_for_bucket([])])

    def test_deterministic_build_micro_roots(self):
        logs = [log(s) for s in range(10)]
        a = build_micro_roots(logs, TimerEnum.MODERATE_10S)
        b = build_micro_roots(logs, TimerEnum.MODERATE_10S)
        self.assertEqual(a, b)
        self.assertEqual(len(a), 6)


if __name__ == "__main__":
    unittest.main()