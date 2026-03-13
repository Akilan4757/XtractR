# SECTION 1 — FULL MICRO-LEVEL ASCII ARCHITECTURAL DIAGRAM
```
+-------------------------------------------------------------------------------------------------------------------+
|                                              XTRACTR FORENSIC PLATFORM ARCHITECTURE                               |
+-------------------------------------------------------------------------------------------------------------------+
|                                                                                                                   |
|  [USER ENVIRONMENT: Untrusted Host OS, Untrusted Clock, Untrusted File System]                                    |
|         |                                                                                                         |
|         v                                                                                                         |
|  [main.py] -------->(1) init / ingest / scan / run-plugins / process / report / export                            |
|         |                                                                                                         |
|         +--> (A) [core/environment.py] => (Measured Boot) Computes Merkle root of all .py source files.           |
|         |                                                                                                         |
|         +--> (B) [core/crypto.py] => Prompts Passphrase. Decrypts/Generates BestAvailableEncryption Ed25519 keys. |
|         |                            Generates investigator.crt (X.509). Provides IdentityManager.                |
|         |                                                                                                         |
|         +--> (C) [core/time_provider.py] => Validates LC_ALL=C, TZ=UTC, PYTHONHASHSEED=0 env vars.                |
|         |                                                                                                         |
|         +--> (D) [core/database.py] => Manages case.db (SQLite) & case_custody_ledger.jsonl (Append-Only Log).    |
|         |                              Logs CASE_INIT with Measured Boot Hash as Source Hash.                     |
|         |                                                                                                         |
|         +--> (E) [core/ingest.py] => Resolves physical path to Virtual File System (Abstracts OS anomalies).      |
|         |             |                                                                                           |
|         |             v                                                                                           |
|         |        [core/vfs/*] => Read-only access boundaries (base.py, directory.py, archive.py, tsk.py)          |
|         |                                                                                                         |
|         +--> (F) [core/baseline.py] => Walk VFS. Hash every physical evidence file. Save to baseline_files table. |
|         |                                                                                                         |
|         +--> (G) [core/plugin_engine.py] => ZERO TRUST PLUGIN ORCHESTRATOR                                        |
|         |             |--> (1) Pre-execution Re-hash: Hashes plugin .py file on disk. Compares to discovery hash. |
|         |             |--> (2) Process Isolation: Spawns ProcessPoolExecutor.                                     |
|         |             |--> (3) Resource Constraints: Restricts stdout size, artifact count, execution time.       |
|         |             |                                                                                           |
|         |             v                                                                                           |
|         |        [plugins/*.py] => Untrusted Parsers (sms_parser, calllog_parser, media_scanner, etc.)            |
|         |             |--> Output: Serialized Artifact objects.                                                   |
|         |                                                                                                         |
|         +--> (H) [core/artifact_validator.py] & [core/plugin_interface.py] => Schema validation over JSON IPC.    |
|         |                                                                                                         |
|         +--> (I) [core/timeline.py] & [core/correlation.py] => Orders events deterministically (UTC monotonic).   |
|         |                                                                                                         |
|         +--> (J) [core/reporting/generator.py] => Converts DB states into HTML/JSON report.                      |
|         |             |--> Reads artifacts, output 11-Tab HTML Viewer.                                            |
|         |                                                                                                         |
|         +--> (K) [core/export.py] => EXPORT AND FINAL SEALING PHASE                                               |
|                       |--> TOCTOU check: Ask VFS to re-read & re-hash ALL files, compare vs baseline.             |
|                       |      (If mismatch -> Abort with Exit Code 10, Log TOCTOU_TAMPER_DETECTED)                 |
|                       |--> CALL [core/integrity.py] => Compute Artifact Root, Log Root, Evidence Root.            |
|                       |                                Combine to System Root. Create seal.json payload.          |
|                       |--> CALL [core/crypto.py] => Sign canonicalized seal.json payload with Ed25519 Private Key.|
|                       |--> CALL [core/tsa.py] => Transmit SHA-256 seal digest over HTTPS to RFC 3161 TSA.         |
|                       |                          Write signed TSA token to seal_tsa.tsr.                          |
|                       +--> Create sealed standard ZIP bundle.                                                     |
|                                                                                                                   |
|===================================================================================================================|
|  [xtractr_verify.py] => INDEPENDENT VERIFIER PATH (Post-Export)                                                   |
|         |--> Reads ZIP or Dir. Extract public key from investigator.crt.                                          |
|         |--> Recomputes Merkle roots (Artifacts, Logs, Evidence) linearly.                                        |
|         |--> Verifies Dual Ledger: Asserts JSONL Log Hashes == SQLite Log Hashes (Mutation defense).              |
|         |--> Applies public key verify() to digital signatures. Check TSA presence.                               |
|         +--> Emits Exit Code 0 (Green) or Exit Code > 0 (Red).                                                    |
+-------------------------------------------------------------------------------------------------------------------+
```
# SECTION 2 — EXECUTION FLOW WALKTHROUGH

1. Initialization Phase (`main.py init`):
   - User executes `main.py init --case-id ID --output /path --passphrase SECRET`.
   - `core/time_provider.py` enforces constraints, checking environment variables for strict UTC logic.
   - `core/crypto.py` instantiates an identity mechanism, decrypting or generating Ed25519 keys with BestAvailableEncryption and an X.509 certificate.
   - `core/database.py` spins up `case.db` and the dual-ledger `case_custody_ledger.jsonl`.
   - `core/environment.py` runs Measured Boot, hashing all source files in core/, orchestrator/, plugins/. Logs the root hash as a genesis event.

2. Evidence Ingestion and Baseline (`main.py scan`):
   - `core/ingest.py` routes the physical path to a Virtual File System (VFS).
   - `core/baseline.py` takes control, walking the VFS and hashing every physical evidence file to formulate the `baseline_files` state.

3. Automated Extraction (`main.py run-plugins`):
   - `core/plugin_engine.py` re-hashes the plugin `.py` source on disk right before execution to detect mid-run tampering.
   - The plugin runs inside a `ProcessPoolExecutor` with rigid constraints.
   - Outputs are validated via `core/artifact_validator.py` and logged to `derived_artifacts`. Custody events securely write to the SQLite and JSONL ledgers.

4. Timeline and Correlation (`main.py process`):
   - `core/timeline.py` explicitly sorts timestamped artifacts inside a deterministic array sequence.
   - `core/correlation.py` builds relationship matrices from valid data.

5. Reporting (`main.py report`):
   - `core/reporting/generator.py` parses tables, formatting SMS, Calls, Media, etc., into an 11-tab interactive HTML Report output.
   - `core/reporting/generator.py` produces the interactive HTML forensic report.

6. Final Sealing (`main.py export`):
   - `core/export.py` runs the TOCTOU (Time-Of-Check Time-Of-Use) sequence: The VFS actively re-reads and re-hashes every evidence file and compares it to `baseline_files`. (Tampering causes a `SystemExit(10)` abort).
   - `core/integrity.py` calculates the Artifact Root and Log Root (Merkle Trees), blending them into a System Root.
   - A canonical `seal.json` is mapped and digitally signed by `core/crypto.py`.
   - `core/tsa.py` anchors the cryptographical seal Hash over HTTPS to an external RFC 3161 TSA server.
   - Packages ZIP.

7. Verification Phase (`xtractr_verify.py`):
   - Outside runtime. Reads the unzipped directory.
   - Evaluates JSONL vs SQLite dual ledgers for line-by-line hash congruency (Catches DB editing).
   - Re-compiles all Merkle Trees. Re-hashes all evidence. Validates signatures using the X.509 public key extract.

# SECTION 3 — CRYPTOGRAPHIC DEPENDENCY GRAPH

[ Investigator Passphrase ] 
         |
         v
[ Ed25519 Private Key ] -----(Signs)------> [ seal.json payload ]
         ^                                           ^
         | (Binds Identity)                          | (Aggregates Hashes)
[ X.509 Certificate ]                                |
                                                     +---- [ System Root ]
                                                              /        \
                                            [ Artifact Root ]     [ Log Root ]
                                                     |                  |
                               (Merkle Leaf) [ SHA-256(Artifact) ]   [ SHA-256(Log Entry ^ Prev_Hash) ]
                                                                                |
                                                                         [ SHA-256(Source Code) ] (Measured Boot Entry)
                                                                         
Tamper Cascades:
- Changing a DB row changes `this_event_hash`, fracturing the `prev_event_hash` linkage of the NEXT event, failing Log Root verification.
- Changing an evidence file fails the pre-export TOCTOU physical re-hash. Post-export, it fails the Evidence Root recalculation.
- Time shifting fails TSA external signature bounds.

# SECTION 4 — TRUST MODEL BOUNDARIES

WHAT IS GUARANTEED:
- Ledger Immutability: Post-ingest event sequence modifications are cryptographically mathematically exposed.
- Source Identity Authentication: Cryptographic signatures bind output artifacts to the defined Passphrase/X.509 configuration.
- Time Objectivity: Integration with RFC 3161 completely disables local OS timestamp reliance for the final chronological seal.

WHAT IS NOT GUARANTEED:
- DMA / Hardware Isolation: Total bare-metal isolation from memory-mapped rootkits reading RAM directly.

WHAT IS ASSUMED:
- Underlying Ed25519 arithmetic and Python SHA-256 logic are fundamentally devoid of flaws or local backdoors.
- The external network TSA provides accurate time and follows protocol logic.

ADVERSARY CLASSES MITIGATED:
- Malicious Modifiers (Database or Physical Evidence Swapping)
- Plugin Injection Attacks (Mid-run Script Edits)
- Chronological Spoofing (OS Timezone alteration)

