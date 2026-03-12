# XtractR Threat Model & Security Assumptions

## 1. System Scope
XtractR is a **Forensic Execution Governance Framework** designed for the triage and acquisition of Android artifacts in a controlled, non-hostile laboratory environment.

**Validated Scope:**
- Android SMS (SQLite)
- Chrome History (SQLite)
- Device Accounts (SQLite)
- Media Files (JPG, PNG, MP4)

## 2. Adversary Profile
We assume the following adversary capabilities:
* **Malicious Artifacts:** Evidence files containing malformed data designed to crash parsers (SQL injection, buffer overflow payloads).
* **Time-Limited Attacker:** An adversary attempting to modify evidence during the acquisition window.
* **Malicious Operator (Partial Capability):** An operator with legitimate access attempting selective evidence extraction or omission.

**Mitigation for Malicious Operator:**
Negative search audit logging, immutable custody ledgers, and sealed manifests limit plausible deniability. While these cannot prevent intentional non-execution, they create an immutable trail of *what was executed*, preventing silent omission of searched paths.

**Out of Scope (Explicitly Undefended):**
* **Kernel-Level Rootkits:** Malware residing in the OS kernel that intercepts `read()` calls.
* **Hardware Compromise:** Physically tampered storage controllers.
* **Runtime Memory Injection:** Attacks modifying the Python interpreter memory during execution.

## 3. Defense Surface & Mitigations

| Threat | Component | Mitigation Strategy | Status |
| :--- | :--- | :--- | :--- |
| **Evidence Tampering** | Governance Core | Active Immutability Checks (Depth Scan) | ✅ Enforced |
| **Parser Exploits** | Orchestrator | Read-Only Schema Validation (Deep Check) | ✅ Enforced |
| **Chain of Custody Gaps** | Ledger System | Monotonic Append-Only Logging | ✅ Enforced |
| **False Negatives** | Discovery Engine | Negative Search Audit Logging | ✅ Enforced |
| **Replay Attacks** | Governance Core | HMAC-SHA256 Signed Tokens (Path+Time Bound) | ✅ Enforced |

## 4. Residual Risks
* **Single-Process Architecture:** Parser crashes may terminate the acquisition pipeline.
* **Filesystem Race Conditions:** Time-of-Check/Time-of-Use (TOCTOU) windows exist, minimized by immediate locking.
