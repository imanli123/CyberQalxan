from __future__ import annotations
from abc import ABC, abstractmethod
from typing import List, Optional

from fastapi import Request

from common.models import LogEntry


class SIEMIntegration(ABC):
    """Abstraction over a SIEM backend (Wazuh, Splunk, ...).

    Both the Oracle (webhook ingestion + alert injection) and the Auditor
    (historical log retrieval + alert injection) talk to the SIEM exclusively
    through this interface.
    """

    @abstractmethod
    def verify_webhook(self, request: Request) -> bool:
        """Authenticate an incoming webhook payload."""

    @abstractmethod
    def parse_payload(self, body) -> List[LogEntry]:
        """Convert a raw webhook body into LogEntry objects.

        `LogEntry.raw` is a canonical, deterministic serialization of the
        event (sorted JSON keys) so both the Oracle and the Auditor hash the
        exact same bytes.
        """

    @abstractmethod
    def trigger_alert(self, doc: dict) -> None:
        """Inject a CyberQalxan integrity alert into the SIEM."""

    @abstractmethod
    def fetch_historical_logs(self, start_time: str, end_time: str, limit: int = 10000) -> Optional[List[LogEntry]]:
        """Fetch logs for a time window.

        Returns `None` when the SIEM is unreachable/failed (distinct from an
        empty window, which returns `[]`).
        """
