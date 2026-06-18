2. Text-Based Breakdown & Configuration

Script 1: Oracle_Ingestion.py (The Shield)

This script runs on the SIEM server. Its sole job is to catch logs, secure them, and push them out.

WebhookListener (Class)

Config: Runs on 0.0.0.0:5000. Uses FastAPI.

Role: Provides the endpoint for Wazuh to push JSON streams continuously.

RAM_Buffer (Class)

Config: Strict memory-management limits. Uses payload-driven deterministic bucketing.

Role: Sorts logs into micro-buckets based on the receipt timestamp text. Enforces the 3-second grace period at the end of the minute.

AI_ThreatEngine (Class)

Config: Loads lightweight ML dependencies. Wakes up every 5 minutes.

Role: Analyzes recent log velocity and outputs the timer_enum (0=60s, 1=5s, 2=10s) to dictate how tightly the RAM_Buffer slices the data.

MerkleRollupEngine (Class)

Role: Executes the recursive SHA-256 math to convert raw text logs into the micro_roots array and the final super_root.

TPM_HardwareSigner (Class)

Config: Binds to Linux /dev/tpmrm0. Contains the PCR sealing configuration (tying the key to the script's SHA-256 hash).

Role: Sends the super_root to the motherboard's silicon. Returns the unforgeable digital signature.

Broadcaster (Class)

Role: Packages the Super Root, Enum, Array, and Signature into one JSON object and POSTs it to the Sentinels over the LAN.

Script 2: Sentinel_Node.py (The Agent)

This script runs on existing enterprise servers (Windows/Linux). It forms the decentralized network.

NodeAPI (Class)

Config: Lightweight FastAPI instance.

Role: Listens for proposed blocks from the Oracle, and serves historical block requests to the Auditor.

CryptoVerifier (Class)

Config: Hardcodes the Oracle's Public Key.

Role: First line of defense. The exact millisecond a block arrives, it runs a cryptographic signature check. If it fails, the packet is instantly dropped.

ConsensusEngine (Class)

Config: Contains the IP list of the 5 other Sentinel nodes.

Role: Executes a lightweight Proof of Authority (PoA) gossip check to ensure all nodes received the exact same payload before saving.

LedgerDatabase (Class)

Config: Uses Python's native sqlite3.

Role: Append-only local storage. Maps the timestamp to the JSON_Payload. Completely file-based, requiring zero database installation.

Script 3: Stateful_Auditor.py (The Detective)

This script runs continuously in the background to guarantee historical immutability.

ThreeTierScheduler (Class)

Config: Limits concurrent threads to guarantee API load never exceeds ~9.4 queries/min.

Role: Manages the timing for the Vanguard (1 min behind), the 24-Hour Sweep, and the 30-Day random Spot-Checks.

SIEM_Puller (Class)

Config: Holds OpenSearch/Wazuh REST API credentials (Read-Only).

Role: Executes GET requests based on the timeframes dictated by the scheduler.

LedgerReader (Class)

Role: Queries a random Sentinel node to fetch the trusted blockchain payload for the targeted timeframe.

VerificationEngine (Class)

Role: Reads the timer_enum from the Ledger Payload, mimics the Oracle's behavior to rebuild the Micro-Roots from the pulled SIEM data, and compares the arrays index-by-index.

AlertManager (Class)

Role: Triggered only upon a mismatch. Formats a critical alert containing the exact 5-second window where the retroactive tamper occurred.