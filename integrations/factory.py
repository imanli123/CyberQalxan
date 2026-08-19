from __future__ import annotations

from config import settings
from integrations.base_siem import SIEMIntegration


def load_siem_integration() -> SIEMIntegration:
    """Return the SIEM integration configured via `settings.SIEM_TYPE`."""
    siem_type = settings.SIEM_TYPE.strip().lower()
    if siem_type == "wazuh":
        from integrations.wazuh import WazuhIntegration
        return WazuhIntegration()
    if siem_type == "splunk":
        from integrations.splunk import SplunkIntegration
        return SplunkIntegration()
    raise ValueError(f"Unsupported SIEM_TYPE: {settings.SIEM_TYPE!r}")
