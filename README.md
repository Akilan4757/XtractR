<p align="center">
  <img src="https://img.shields.io/badge/XtractR-Forensic%20Platform-0d1117?style=for-the-badge&labelColor=161b22&color=58a6ff" alt="XtractR" />
</p>

<h1 align="center">XtractR</h1>

<p align="center">
  <strong>Digital Forensics Evidence Extraction Engine</strong><br/>
  <em>Cryptographically sealed artifact extraction pipeline for Android devices</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/crypto-Ed25519-6C3483?style=flat-square" />
  <img src="https://img.shields.io/badge/integrity-Merkle%20Trees-1ABC9C?style=flat-square" />
  <img src="https://img.shields.io/badge/status-Research-yellow?style=flat-square" />
  <img src="https://img.shields.io/badge/platform-Linux-FCC624?style=flat-square&logo=linux&logoColor=black" />
</p>


## What is XtractR?

**XtractR** is a forensic evidence extraction and analysis engine for Android device data. It processes device extractions through a cryptographically sealed pipeline — from raw artifact parsing to signed, timestamped evidence bundles.

Every action is logged in an immutable Merkle-chained custody ledger. Every evidence file is baselined, hashed, and sealed. Every output is digitally signed with Ed25519 keys.

---

## Key Features

| Feature | Description |
|---|---|
| 🔗 **Merkle-Chained Custody Ledger** | Dual-ledger system (SQLite + JSONL) with hash-linked event chains — any modification breaks the chain |
| 🛡️ **Cryptographic Sealing** | Ed25519 digital signatures + RFC 3161 timestamping for every critical artifact |
| 🗂️ **Virtual File System** | Read-only VFS abstraction supporting raw directories, ZIP/TAR archives, and E01/RAW disk images |
| 🔌 **Zero-Trust Plugin Engine** | Process-isolated parsers with pre-execution integrity checks — plugins are re-hashed before every run |
| 🔒 **TOCTOU Defense** | Pre-export re-hash of all evidence files detects tampering between scan and seal |
| ✅ **Independent Verifier** | Standalone `xtractr_verify.py` audits case integrity without the main platform |
| 📊 **Interactive HTML Report** | Multi-tab forensic report with views for each artifact category |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     XtractR Forensic Pipeline                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  main.py ─── CLI Entry Point                                    │
│     │                                                           │
│     ├── init ──────► Identity (Ed25519) + Database + Env Boot   │
│     ├── ingest ────► VFS Mount (Dir / ZIP / E01)                │
│     ├── scan ──────► SHA-256 Baseline of All Evidence Files     │
│     ├── run-plugins► Zero-Trust Plugin Execution                │
│     │                  ├── SMS Parser                           │
│     │                  ├── Call Log Parser                      │
│     │                  ├── Contacts Parser                      │
│     │                  ├── Chrome History Parser                │
│     │                  ├── WhatsApp / Telegram / Instagram      │
│     │                  ├── Email Parser                         │
│     │                  ├── Media Scanner (EXIF + Hashing)       │
│     │                  ├── Location Parser                      │
│     │                  ├── Installed Apps Parser                │
│     │                  └── Accounts Parser                      │
│     ├── process ───► Timeline Construction + Correlation        │
│     ├── report ────► HTML Report Generation                     │
│     └── export ────► TOCTOU Check → Merkle Seal → Sign → ZIP    │
│                                                                 │
│  xtractr_verify.py ─── Independent Post-Export Verifier         │
│     ├── Dual Ledger Consistency (JSONL ↔ SQLite)                │
│     ├── Merkle Root Recomputation                               │
│     ├── Signature Verification (Ed25519)                        │
│     └── TSA Token Validation                                    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
XtractR/
├── main.py                     # CLI entry point
├── xtractr_verify.py           # Standalone integrity verifier
├── XtractR.sh                  # Shell launcher
├── Dockerfile                  # Container deployment
├── Makefile                    # Build & run automation
├── requirements.txt            # Python dependencies
├── .env.forensic               # Deterministic execution environment
│
├── core/                       # Engine core
│   ├── crypto.py               # Ed25519 key management & signing
│   ├── database.py             # SQLite case database + dual ledger
│   ├── baseline.py             # Evidence file hashing & drift detection
│   ├── plugin_engine.py        # Zero-trust plugin orchestrator
│   ├── export.py               # Bundle creation & sealing
│   ├── integrity.py            # Merkle tree computation
│   ├── timeline.py             # Deterministic timeline builder
│   ├── correlation.py          # Cross-artifact correlation
│   ├── ingest.py               # Evidence source ingestion
│   ├── tsa.py                  # RFC 3161 timestamp authority client
│   ├── reporting/              # HTML report generator
│   └── vfs/                    # Virtual File System (Dir / ZIP / E01)
│
├── plugins/                    # Artifact parsers (process-isolated)
│   ├── sms_parser.py           # SMS/MMS extraction
│   ├── calllog_parser.py       # Call history
│   ├── contacts_parser.py      # Contacts database
│   ├── chrome_history_parser.py# Browser history
│   ├── whatsapp_parser.py      # WhatsApp messages
│   ├── telegram_parser.py      # Telegram messages
│   ├── instagram_parser.py     # Instagram data
│   ├── email_parser.py         # Email extraction
│   ├── media_scanner.py        # Media files (EXIF, hashing)
│   ├── location_parser.py      # GPS & location data
│   ├── installed_apps_parser.py# Installed packages
│   └── accounts_parser.py      # Device accounts
│
├── orchestrator/               # Pipeline orchestration
├── tests/                      # Test suite (17 test files)
└── docs/                       # Documentation
```

---

## Getting Started

### Prerequisites

- **Python 3.10+**
- **Linux** (tested on Kali, Ubuntu, Debian)
- Optional: `pytsk3` and `libewf-python` for disk image support

### Installation

```bash
git clone https://github.com/Akilan4757/XtractR.git
cd XtractR

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
```

### Usage

```bash
# Initialize a new case
python3 main.py init \
  --case-id "CASE_001" \
  --output ./cases/my_case \
  --investigator-name "Officer Name"

# Link evidence source
python3 main.py ingest --case-dir ./cases/my_case --source /path/to/evidence

# Baseline all evidence files
python3 main.py scan --case-dir ./cases/my_case

# Run all parsers
python3 main.py run-plugins --case-dir ./cases/my_case

# Build timeline & correlations
python3 main.py process --case-dir ./cases/my_case

# Generate report
python3 main.py report --case-dir ./cases/my_case

# Seal & export evidence bundle
python3 main.py export --case-dir ./cases/my_case
```

---

## Security Model

| Component | Algorithm | Purpose |
|---|---|---|
| **Digital Signatures** | Ed25519 | Binds investigator identity to outputs |
| **File Integrity** | SHA-256 | Hashes every evidence file and artifact |
| **Merkle Trees** | SHA-256 binary tree | Aggregates hashes into verifiable roots |
| **Key Encryption** | scrypt (BestAvailableEncryption) | Protects private key with passphrase |
| **Timestamping** | RFC 3161 TSA | External time proof via trusted authority |

### Tamper Detection

```
Modify a DB row     → Breaks log_root  → seal.json verification fails
Modify evidence file → Breaks TOCTOU    → Export aborts (exit code 10)
Modify sealed bundle → Breaks manifest  → xtractr_verify.py detects
Modify plugin code   → Breaks code hash → Plugin engine refuses execution
```

### Independent Verification

```bash
python3 xtractr_verify.py --case-dir ./unzipped_bundle --pub-key ./investigator.pub
```

---

## Docker

```bash
docker build -t xtractr .
docker run --env-file .env.forensic \
  -v /path/to/evidence:/evidence:ro \
  -v /path/to/output:/output \
  xtractr init --case-id CASE_001 --output /output/case --investigator-name "Officer"
```

---

## Testing

```bash
pytest tests/ -v
```

---

## Documentation

| Document | Description |
|---|---|
| [Technical Architecture](XTRACTR_TECHNICAL_ARCHITECTURE.md) | System architecture deep-dive |
| [Architecture Overview](docs/ARCHITECTURE.md) | System diagrams and data flow |
| [Threat Model](THREAT_MODEL.md) | Adversary profiles and defense surface |
| [Forensic Integrity](docs/forensic_integrity.md) | Integrity model documentation |

---

## License

**Proprietary — Personal Use & Research Only**

See [LICENSE](LICENSE) for full terms. You may use this software for personal, non-commercial, and research purposes only. Redistribution, modification, and commercial use are not permitted without written consent.

© 2026 Akilan. All rights reserved.

---
