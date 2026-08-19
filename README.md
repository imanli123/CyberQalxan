# CyberQalxan

Off-Chain Merkle Batching middleware that cryptographically anchors SIEM logs (Wazuh/OpenSearch, Splunk) onto a private decentralized ledger to guarantee audit-trail immutability against insider tampering.

## Components

| Role      | File                              | Responsibility                                              |
| --------- | --------------------------------- | ----------------------------------------------------------- |
| Oracle    | `oracle/oracle_ingestion.py`      | Ingests the SIEM webhook, rolls logs into a Merkle root, signs it, broadcasts blocks. |
| Sentinel  | `sentinel/sentinel_node.py`       | Verifies Oracle signatures, PoA gossip, append-only ledger, admin/health API. |
| Auditor   | `auditor/stateful_auditor.py`     | Re-verifies historical windows and fires integrity alerts on mismatch. |
| Integrations | `integrations/`                | SIEM abstraction (Wazuh, Splunk) behind a single factory.    |
| Core      | `common/` (`crypto`, `models`, `identity`) | Merkle math, schemas, RSA/TPM identity.           |
| Config    | `config/settings.py`              | All settings; reads `CQ_*` env vars / `.env`.                |
| CLI       | `cli/setup.py`, `cli/manage.py`   | One-time setup + ops (status, audit, add/remove node).       |
| Tests     | `tests/`                          | `python -m unittest discover -s tests`                       |

## Architecture

1. **Wazuh/Splunk** pushes events to `POST /webhook` (Oracle, port 5000). The webhook is authenticated (`X-CyberQalxan-Token` for Wazuh, `Authorization: Splunk <token>` for Splunk).
2. Oracle buffers events into per-minute buckets (3s grace). The AI threat engine picks a `TimerEnum` (60s/30s/15s/10s/5s) from log velocity; the minute is sliced into timer-aligned sub-buckets, each reduced to a SHA-256 **micro-root**, then to a **super-root**.
3. The super-root is signed with the Oracle's RSA identity (or TPM 2.0) and broadcast as a `SealedBlock` to the 5 Sentinels (port 5100).
4. Sentinels verify the signature (fail-closed, no fallback), run PoA gossip, and store the block in an append-only SQLite ledger. `confirmed = signatures >= quorum`.
5. The Auditor pulls the same logs from the SIEM for each window, rebuilds the micro-roots with the block's `timer_enum`, and compares index-by-index. Any mismatch triggers a critical SIEM alert with the **exact tampered time window**.

## Quickstart

```bash
# 1. configure identities, SIEM creds, node discovery
python -m cli.setup

# 2. run the three daemons
python -m oracle.oracle_ingestion
python -m sentinel.sentinel_node <ip> [identity_key_path]
python -m auditor.stateful_auditor

# ops
python -m cli.manage status --target 192.168.1.10
python -m cli.manage audit
python -m cli.manage add-node 192.168.1.15
python -m cli.manage remove-node 192.168.1.15
```

## Configuration

`config/settings.py` is the single source of truth. Sensitive values can be overridden via env vars (`.env` at the project root, written by `cli/setup.py`): `CQ_SIEM_TYPE`, `CQ_WAZUH_INDEXER_PASSWORD`, `CQ_WAZUH_WEBHOOK_TOKEN`, `CQ_SPLUNK_HEC_TOKEN`, `CQ_CLUSTER_PASSWORD`, `CQ_CLUSTER_ADMIN_PASSWORD`, `CQ_SENTINEL_IPS`, `CQ_IDENTITY_KIND`.

`IDENTITY_KIND` is `auto` (TPM via `tpm2-pytss`, falls back to an encrypted RSA key file), `tpm`, or `file`. RSA keys are stored with `BestAvailableEncryption` using the cluster password.

## Security notes

- Signature verification is **fail-closed**: a Sentinel rejects any block when the Oracle public key is unavailable.
- The webhook and `/public_key` endpoints require a shared token / cluster admin password.
- Sentinel admin operations (`/admin/add-node`, `/admin/evict`) are authorized with an HMAC over the payload using the cluster admin password.
- A dead-man switch on each Sentinel alerts when the Oracle stops delivering blocks.
- Real TPM signing requires provisioning with `tpm2-tools`; see `common/tpm_identity.py`.