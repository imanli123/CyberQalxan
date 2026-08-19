from __future__ import annotations
from enum import IntEnum
from pydantic import BaseModel
from typing import List, Optional


class TimerEnum(IntEnum):
    STANDARD_60S = 0
    AGGRESSIVE_5S = 1
    MODERATE_10S = 2
    MODERATE_15S = 3
    MODERATE_30S = 4


class LogEntry(BaseModel):
    raw: str
    timestamp: str


class MicroBucket(BaseModel):
    window_start: str
    window_end: str
    logs: List[LogEntry]


class MerkleBatch(BaseModel):
    micro_roots: List[str]
    super_root: str


class SealedBlock(BaseModel):
    super_root: str
    timer_enum: TimerEnum
    micro_roots: List[str]
    signature: str
    timestamp: str


class SentinelBlock(BaseModel):
    block_id: str
    payload: SealedBlock
    node_signatures: List[str]
    confirmed: bool = False


class SIEMQueryRange(BaseModel):
    start_time: str
    end_time: str


class AuditReport(BaseModel):
    timeframe: SIEMQueryRange
    passed: bool
    mismatched_windows: List[str]
    recovered_root: Optional[str]
    stored_root: Optional[str]
