from __future__ import annotations
import hashlib
from datetime import datetime
from typing import Dict, List, Optional

from common.models import LogEntry, TimerEnum

EMPTY_BUCKET_PLACEHOLDER = "CYBERQXALXAN_EMPTY_BUCKET"

TIMER_BUCKET_SECONDS: Dict[TimerEnum, int] = {
    TimerEnum.STANDARD_60S: 60,
    TimerEnum.AGGRESSIVE_5S: 5,
    TimerEnum.MODERATE_10S: 10,
    TimerEnum.MODERATE_15S: 15,
    TimerEnum.MODERATE_30S: 30,
}


def bucket_size_for(timer_enum) -> int:
    return TIMER_BUCKET_SECONDS.get(TimerEnum(timer_enum), 60)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_log(raw_log: str) -> str:
    return sha256(raw_log.encode("utf-8"))


def parse_timestamp(value: str) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def build_merkle_tree(leaves: List[str]) -> List[str]:
    if not leaves:
        return []
    current_level = leaves[:]
    while len(current_level) > 1:
        next_level = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            right = current_level[i + 1] if i + 1 < len(current_level) else left
            next_level.append(sha256((left + right).encode("utf-8")))
        current_level = next_level
    return current_level


def micro_root_for_bucket(bucket_logs: List[LogEntry]) -> str:
    if not bucket_logs:
        return sha256(EMPTY_BUCKET_PLACEHOLDER.encode("utf-8"))
    leaves = [hash_log(log.raw) for log in bucket_logs]
    return build_merkle_tree(leaves)[0]


def slice_logs_into_buckets(logs: List[LogEntry], timer_enum: TimerEnum) -> List[List[LogEntry]]:
    """Split a minute of logs into timer-aligned sub-buckets (60s/30s/15s/10s/5s)."""
    bucket_size = bucket_size_for(timer_enum)
    num_buckets = max(1, 60 // bucket_size)
    buckets: List[List[LogEntry]] = [[] for _ in range(num_buckets)]
    for log in logs:
        ts = parse_timestamp(log.timestamp)
        if ts is None:
            continue
        seconds = ts.second + ts.microsecond / 1_000_000.0
        idx = min(int(seconds // bucket_size), num_buckets - 1)
        buckets[idx].append(log)
    return buckets


def build_micro_roots(logs: List[LogEntry], timer_enum: TimerEnum) -> List[str]:
    """Deterministic micro-roots for a set of logs under a timer enum.

    Both the Oracle and the Auditor must use this exact function so that the
    per-bucket roots (and their order) can be reproduced identically.
    """
    return [micro_root_for_bucket(b) for b in slice_logs_into_buckets(logs, timer_enum)]


def build_super_root(micro_roots: List[str]) -> str:
    if not micro_roots:
        return sha256(EMPTY_BUCKET_PLACEHOLDER.encode("utf-8"))
    return build_merkle_tree(micro_roots)[0]
