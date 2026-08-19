import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_dotenv():
    env_path = os.path.join(PROJECT_ROOT, ".env")
    if not os.path.exists(env_path):
        return
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


_load_dotenv()

# ---------------------------------------------------------------------------
# Oracle (The Shield)
# ---------------------------------------------------------------------------
ORACLE_HOST = "0.0.0.0"
ORACLE_PORT = 5000
ORACLE_IDENTITY_KEY_PATH = os.path.join(PROJECT_ROOT, "config", "oracle_identity.pem")
ORACLE_PUBLIC_KEY_PATH = os.path.join(PROJECT_ROOT, "config", "oracle_public_key.pem")

RAM_BUFFER_MAX_MB = 512
RAM_BUFFER_GRACE_SECONDS = 3

AI_THREAT_ENGINE_INTERVAL_SECONDS = 300
AI_THREAT_ENGINE_WINDOW_MINUTES = 5

# ---------------------------------------------------------------------------
# Merkle / timer enum (seconds per sub-bucket within a minute)
# ---------------------------------------------------------------------------
TIMER_ENUM_60S = 0
TIMER_ENUM_5S = 1
TIMER_ENUM_10S = 2
TIMER_ENUM_15S = 3
TIMER_ENUM_30S = 4

MERKLE_ROLLUP_BATCH_SIZE = 1000

# ---------------------------------------------------------------------------
# Identity / TPM
# ---------------------------------------------------------------------------
# auto | tpm | file
IDENTITY_KIND = os.getenv("CQ_IDENTITY_KIND", "auto")
TPM_DEVICE_PATH = os.getenv("CQ_TPM_DEVICE_PATH", "/dev/tpm0")
TPM_PCR_SELECTION = [0, 1, 2, 3]
CLUSTER_PASSWORD = os.getenv("CQ_CLUSTER_PASSWORD", "")

# ---------------------------------------------------------------------------
# Sentinel (The Agent)
# ---------------------------------------------------------------------------
SENTINEL_API_PORT = int(os.getenv("CQ_SENTINEL_API_PORT", "5100"))


def _default_node_ips():
    raw = os.getenv("CQ_SENTINEL_IPS", "")
    if raw:
        return [ip.strip() for ip in raw.split(",") if ip.strip()]
    return [
        "192.168.1.10",
        "192.168.1.11",
        "192.168.1.12",
        "192.168.1.13",
        "192.168.1.14",
    ]


SENTINEL_NODE_IPS = _default_node_ips()

SENTINEL_ORACLE_PUBLIC_KEY_PATH = os.path.join(PROJECT_ROOT, "config", "oracle_public_key.pem")
SENTINEL_PUBLIC_KEY_REGISTRY_PATH = os.path.join(PROJECT_ROOT, "config", "sentinel_registry.json")
SENTINEL_IDENTITY_KEY_PATH = os.path.join(PROJECT_ROOT, "config", "sentinel_identity.pem")

LEDGER_DB_PATH = os.path.join(PROJECT_ROOT, "sentinel", "ledger.db")

DEAD_MAN_SWITCH_INTERVAL_SECONDS = 60
DEAD_MAN_SWITCH_THRESHOLD_SECONDS = 240
UDP_DISCOVERY_PORT = 9999

# ---------------------------------------------------------------------------
# Auditor (The Detective)
# ---------------------------------------------------------------------------
AUDITOR_MAX_CONCURRENT_THREADS = 3
AUDITOR_VANGUARD_DELAY_SECONDS = 60
AUDITOR_24H_SWEEP_INTERVAL_SECONDS = 86400
AUDITOR_30D_CHECK_INTERVAL_SECONDS = 2592000
AUDITOR_ALERT_DEDUP_WINDOW_SECONDS = 86400

# ---------------------------------------------------------------------------
# SIEM integration (wazuh | splunk)
# ---------------------------------------------------------------------------
SIEM_TYPE = os.getenv("CQ_SIEM_TYPE", "wazuh").strip().lower()

WAZUH_API_BASE_URL = "http://localhost:55000"
WAZUH_API_USERNAME = "wazuh-readonly"
WAZUH_API_PASSWORD = "wazuh-readonly-password"
WAZUH_INDEXER_URL = "http://localhost:9200"
WAZUH_INDEXER_USERNAME = "admin"
WAZUH_INDEXER_PASSWORD = os.getenv("CQ_WAZUH_INDEXER_PASSWORD", "change-me")
WAZUH_ALERTS_INDEX = "wazuh-alerts-4.x"
WAZUH_INDEX_PATTERN = "wazuh-alerts-*"
WAZUH_AGENT_ID = "000"
WAZUH_AGENT_NAME = "CyberQalxan-Cluster"
WAZUH_WEBHOOK_TOKEN = os.getenv("CQ_WAZUH_WEBHOOK_TOKEN", "change-me")
WAZUH_CA_BUNDLE = None

SPLUNK_HEC_URL = "http://localhost:8088"
SPLUNK_HEC_TOKEN = os.getenv("CQ_SPLUNK_HEC_TOKEN", "change-me")
SPLUNK_REST_URL = "http://localhost:8089"
SPLUNK_INDEX = "cyberqalxan"
SPLUNK_CA_BUNDLE = None

SIEM_API_BASE_URL = WAZUH_API_BASE_URL  # backward compatibility
SIEM_API_USERNAME = WAZUH_API_USERNAME
SIEM_API_PASSWORD = WAZUH_API_PASSWORD
SIEM_INDEX_PATTERN = WAZUH_INDEX_PATTERN

ALERT_WEBHOOK_URL = "http://alert-manager:9093/api/v1/alerts"

# ---------------------------------------------------------------------------
# Cluster admin / CLI
# ---------------------------------------------------------------------------
CLUSTER_ADMIN_PASSWORD = os.getenv("CQ_CLUSTER_ADMIN_PASSWORD", "change-me")
SEED_NODE_IP = "192.168.1.10"
LOCAL_IP = "127.0.0.1"
