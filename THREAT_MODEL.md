# XtractR Threat Model & Security Assumptions

## 1. System Scope
XtractR is a **Forensic Execution Governance Framework** designed for the triage and acquisition of Android artifacts in a controlled, non-hostile laboratory environment.

**Validated Scope:**
- Android SMS/MMS (SQLite)
- Call Logs (SQLite)
- Contacts (SQLite)
- Chrome History (SQLite)
- Device Accounts (SQLite)
- Telegram Messages/Media/Contacts (SQLite)
- WhatsApp Messages (SQLite)
- Instagram Messages (SQLite)
- Email Messages/Bodies (SQLite)
- Location Data (SQLite)
- Installed Apps (XML/manifest)
- Media Files (JPG, PNG, MP4, etc. via metadata scanning)

## 2. Adversary Profile
We assume the following adversary capabilities:
* **Malicious Artifacts:** Evidence files containing malformed data designed to crash parsers (SQL injection, buffer overflow payloads).
* **Time-Limited Attacker:** An adversary attempting to modify evidence during the acquisition window.
* **Malicious Operator (Partial Capability):** An operator with legitimate access attempting selective evidence extraction or omission.

**Mitigation for Malicious Operator:**
Immutable custody ledgers (with dual SQLite + JSONL chains) and cryptographically sealed manifests limit plausible deniability. While these cannot prevent intentional non-execution of the tool, they create an immutable trail of *what was executed*, preventing silent omission of searched paths. Any row-level parsing failure is logged to the ledger as `PLUGIN_PARTIAL_FAILURE`.

**Out of Scope (Explicitly Undefended):**
* **Kernel-Level Rootkits:** Malware residing in the OS kernel that intercepts `read()` calls.
* **Hardware Compromise:** Physically tampered storage controllers.
* **Runtime Memory Injection:** Attacks modifying the Python interpreter memory during execution.

## 3. Defense Surface & Mitigations

| Threat | Component | Mitigation Strategy | Status |
| :--- | :--- | :--- | :--- |
| **Evidence Tampering** | Governance Core | Cryptographic baseline hashing & post-hashing TOCTOU validation | **Partial** |
| **Parser Exploits** | Sandbox | Process-isolated execution with strict memory and CPU time limits | **Partial** |
| **Chain of Custody Gaps** | Ledger System | Monotonic SQLite + JSONL dual-linked append-only ledger | **Partial** |
| **Privileged Code Execution** | Plugin Loader | AST static plugin discovery (no parent import) + TOCTOU hashing in child | **Partial** |
| **Tampered Seals** | Sealing Core | Domain-separated RFC 6962 Merkle tree & signed tree roots with an RFC 3161 token request over the signed seal; reply validation remains unimplemented | **Partial** |

## 4. Documentation Alignment Notes
- The verifier requires an out-of-band `--expect-fingerprint` by default. `--allow-unpinned` verifies internal consistency only and does not authenticate the signer.
- Evidence Merkle leaves bind path, size, modification time, and SHA-256. This changes the bundle algorithm; old bundles need a legacy verifier path before compatibility can be claimed.
- RFC 3161 replies are not yet parsed for status, imprint, nonce, certificate chain, or generation time. Token presence alone is not proof of a trusted timestamp.
- **Canary file immutability probes:** Out of Scope / Not Implemented. Tamper detection relies purely on cryptographic baseline re-hashing prior to case export.
- **HMAC signed execution tokens:** Out of Scope / Not Implemented. These controls are not implemented; no HMAC execution tokens or read-only parser database mounts are provided.
- **3-phase copy renaming:** Out of Scope / Not Implemented. Baselining tracks file hashes, and VFS enforces strict read-only access.
- **Negative search logs:** Out of Scope / Not Implemented. Negative-search paths are not comprehensively logged; timeline gaps are not equivalent to a recorded negative search.
