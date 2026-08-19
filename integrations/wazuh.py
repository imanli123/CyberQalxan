from __future__ import annotations
import json
import secrets
from datetime import datetime
from typing import List, Optional

import requests
from fastapi import Request

from config import settings
from common.models import LogEntry
from integrations.base_siem import SIEMIntegration


def _canonical(event: dict) -> str:
    return json.dumps(event, sort_keys=True)


class WazuhIntegration(SIEMIntegration):
    """Wazuh / OpenSearch integration.

    Webhook:   HTTP POST /webhook with header `X-CyberQalxan-Token`.
    Historical logs: Wazuh REST API alerts endpoint.
    Alerts:    index a document into the OpenSearch indexer.
    """

    def __init__(
        self,
        api_base_url: str = None,
        api_username: str = None,
        api_password: str = None,
        indexer_url: str = None,
        indexer_username: str = None,
        indexer_password: str = None,
        alerts_index: str = None,
        index_pattern: str = None,
        agent_id: str = None,
        agent_name: str = None,
        webhook_token: str = None,
        ca_bundle: str = None,
    ):
        self.api_base_url = api_base_url or settings.WAZUH_API_BASE_URL
        self.api_username = api_username or settings.WAZUH_API_USERNAME
        self.api_password = api_password or settings.WAZUH_API_PASSWORD
        self.indexer_url = indexer_url or settings.WAZUH_INDEXER_URL
        self.indexer_username = indexer_username or settings.WAZUH_INDEXER_USERNAME
        self.indexer_password = indexer_password or settings.WAZUH_INDEXER_PASSWORD
        self.alerts_index = alerts_index or settings.WAZUH_ALERTS_INDEX
        self.index_pattern = index_pattern or settings.WAZUH_INDEX_PATTERN
        self.agent_id = agent_id or settings.WAZUH_AGENT_ID
        self.agent_name = agent_name or settings.WAZUH_AGENT_NAME
        self.webhook_token = webhook_token or settings.WAZUH_WEBHOOK_TOKEN
        self.ca_bundle = ca_bundle if ca_bundle is not None else settings.WAZUH_CA_BUNDLE

    def verify_webhook(self, request: Request) -> bool:
        token = request.headers.get("X-CyberQalxan-Token", "")
        return bool(self.webhook_token) and secrets.compare_digest(token, self.webhook_token)

    def parse_payload(self, body) -> List[LogEntry]:
        entries = body if isinstance(body, list) else [body]
        logs: List[LogEntry] = []
        for event in entries:
            if not isinstance(event, dict):
                continue
            timestamp = event.get("timestamp") or event.get("_timestamp") or datetime.utcnow().isoformat()
            logs.append(LogEntry(raw=_canonical(event), timestamp=timestamp))
        return logs

    def trigger_alert(self, doc: dict) -> None:
        index = f"{self.alerts_index}-{datetime.utcnow().strftime('%Y.%m.%d')}"
        payload = dict(doc)
        payload.setdefault("agent", {"id": self.agent_id, "name": self.agent_name})
        payload["timestamp"] = datetime.utcnow().isoformat()
        try:
            requests.post(
                f"{self.indexer_url}/{index}/_doc",
                json=payload,
                auth=(self.indexer_username, self.indexer_password),
                verify=self.ca_bundle or False,
                timeout=10,
            )
        except Exception:
            try:
                requests.post(settings.ALERT_WEBHOOK_URL, json=doc, timeout=5)
            except Exception:
                pass

    def fetch_historical_logs(self, start_time: str, end_time: str, limit: int = 10000) -> Optional[List[LogEntry]]:
        try:
            resp = requests.get(
                f"{self.api_base_url}/api/v1/alerts",
                params={"start_time": start_time, "end_time": end_time, "limit": limit},
                auth=(self.api_username, self.api_password),
                verify=self.ca_bundle or False,
                timeout=30,
            )
        except Exception:
            return None
        if resp.status_code != 200:
            return None

        try:
            data = resp.json()
        except ValueError:
            return None

        events = []
        if isinstance(data, list):
            events = data
        elif isinstance(data, dict):
            events = data.get("hits", {}).get("hits", [])
            events = [e.get("_source", e) for e in events]
        return [LogEntry(raw=_canonical(e) if isinstance(e, dict) else str(e),
                         timestamp=(e.get("timestamp") if isinstance(e, dict) else None) or datetime.utcnow().isoformat())
                for e in events]
