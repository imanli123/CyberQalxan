from __future__ import annotations
import unittest

from common.models import LogEntry
from integrations.factory import load_siem_integration
from integrations.splunk import SplunkIntegration
from integrations.wazuh import WazuhIntegration


class FakeRequest:
    def __init__(self, headers: dict):
        self.headers = headers


class TestWazuh(unittest.TestCase):
    def test_parse_payload_list(self):
        integration = WazuhIntegration(webhook_token="tok")
        body = [{"timestamp": "2026-08-18T12:05:01", "data": {"a": 1}}]
        logs = integration.parse_payload(body)
        self.assertEqual(len(logs), 1)
        self.assertIsInstance(logs[0], LogEntry)
        self.assertEqual(logs[0].raw, '{"data": {"a": 1}, "timestamp": "2026-08-18T12:05:01"}')

    def test_verify_webhook_token(self):
        integration = WazuhIntegration(webhook_token="tok")
        self.assertTrue(integration.verify_webhook(FakeRequest({"X-CyberQalxan-Token": "tok"})))
        self.assertFalse(integration.verify_webhook(FakeRequest({"X-CyberQalxan-Token": "wrong"})))
        self.assertFalse(integration.verify_webhook(FakeRequest({})))

    def test_parse_payload_skips_non_dicts(self):
        integration = WazuhIntegration(webhook_token="tok")
        self.assertEqual(integration.parse_payload([1, "x", None]), [])


class TestSplunk(unittest.TestCase):
    def test_parse_hec_payload(self):
        integration = SplunkIntegration(hec_token="tok")
        body = {"event": {"hello": "world"}, "time": 1786935000}
        logs = integration.parse_payload(body)
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0].raw, '{"hello": "world"}')

    def test_parse_hec_missing_event(self):
        integration = SplunkIntegration(hec_token="tok")
        self.assertEqual(integration.parse_payload({"foo": "bar"}), [])

    def test_verify_webhook_auth_header(self):
        integration = SplunkIntegration(hec_token="tok")
        self.assertTrue(integration.verify_webhook(FakeRequest({"Authorization": "Splunk tok"})))
        self.assertFalse(integration.verify_webhook(FakeRequest({"Authorization": "Splunk nope"})))
        self.assertFalse(integration.verify_webhook(FakeRequest({})))


class TestFactory(unittest.TestCase):
    def test_factory_supported_types(self):
        self.assertTrue(hasattr(load_siem_integration(), "fetch_historical_logs"))

    def test_factory_rejects_unknown(self):
        from unittest.mock import patch

        with patch("config.settings.SIEM_TYPE", "splunkish"):
            with self.assertRaises(ValueError):
                load_siem_integration()


if __name__ == "__main__":
    unittest.main()