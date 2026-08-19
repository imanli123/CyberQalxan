from __future__ import annotations
import json
import secrets
from datetime import datetime, timezone
from typing import List, Optional

import requests
from fastapi import Request

from config import settings
from common.models import LogEntry
from integrations.base_siem import SIEMIntegration


def _canonical(event) -> str:
    if isinstance(event, dict):
        return json.dumps(event, sort_keys=True)
    return json.dumps(str(event), sort_keys=True)


class SplunkIntegration(SIEMIntegration):
    """Splunk integration.

    Webhook:   HTTP POST /webhook with `Authorization: Splunk <HEC token>`.
    Historical logs: Splunk REST jobs/export API.
    Alerts:    POST to the HEC /services/collector endpoint.
    """

    def __init__(
        self,
        hec_url: str = None,
        hec_token: str = None,
        rest_url: str = None,
        index: str = None,
        ca_bundle: str = None,
    ):
        self.hec_url = hec_url or settings.SPLUNK_HEC_URL
        self.hec_token = hec_token or settings.SPLUNK_HEC_TOKEN
        self.rest_url = rest_url or settings.SPLUNK_REST_URL
        self.index = index or settings.SPLUNK_INDEX
        self.ca_bundle = ca_bundle if ca_bundle is not None else settings.SPLUNK_CA_BUNDLE

    def verify_webhook(self, request: Request) -> bool:
        header = request.headers.get("Authorization", "")
        return bool(self.hec_token) and secrets.compare_digest(header, f"Splunk {self.hec_token}")

    def parse_payload(self, body) -> List[LogEntry]:
        if not isinstance(body, dict) or "event" not in body:
            return []
        raw_time = body.get("time")
        if isinstance(raw_time, (int, float)):
            timestamp = datetime.fromtimestamp(raw_time, tz=timezone.utc).isoformat()
        else:
            timestamp = str(raw_time) if raw_time else datetime.utcnow().isoformat()
        return [LogEntry(raw=_canonical(body["event"]), timestamp=timestamp)]

    def trigger_alert(self, doc: dict) -> None:
        try:
            requests.post(
                f"{self.hec_url}/services/collector",
                headers={"Authorization": f"Splunk {self.hec_token}"},
                json={"index": self.index, "sourcetype": "cyberqalxan:integrity", "event": doc},
                verify=self.ca_bundle or False,
                timeout=10,
            )
        except Exception:
            try:
                requests.post(settings.ALERT_WEBHOOK_URL, json=doc, timeout=5)
            except Exception:
                pass

    def fetch_historical_logs(self, start_time: str, end_time: str, limit: int = 10000) -> Optional[List[LogEntry]]:
        search = f'search index={self.index} earliest="{start_time}" latest="{end_time}" | head {limit}'
        try:
            resp = requests.get(
                f"{self.rest_url}/services/search/v2/jobs/export",
                params={"search": search, "output_mode": "json"},
                headers={"Authorization": f"Splunk {self.hec_token}"},
                verify=self.ca_bundle or False,
                timeout=60,
            )
        except Exception:
            return None
        if resp.status_code != 200:
            return None

        logs: List[LogEntry] = []
        for line in resp.iter_lines(decode_unicode=True):
            if not line:
                continue
            try:
                result = json.loads(line)
            except ValueError:
                continue
            raw = result.get("_raw", "")
            timestamp = result.get("_time") or datetime.utcnow().isoformat()
            logs.append(LogEntry(raw=raw, timestamp=timestamp))
        return logs
