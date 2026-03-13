# XTRACTR — Technical Architecture Documentation

**Version:** 1.1.0  
**Schema Version:** 3.0.0  
**Classification:** Internal Technical Reference  
**Purpose:** Internal Technical Reference — System Architecture Specification

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Evidence Acquisition Layer](#2-evidence-acquisition-layer)
3. [Artifact Parsing Layer](#3-artifact-parsing-layer)
4. [Evidence Storage Layer](#4-evidence-storage-layer)
5. [Evidence Integrity Layer](#5-evidence-integrity-layer)
6. [Evidence Ledger](#6-evidence-ledger)
7. [Timeline Reconstruction Engine](#7-timeline-reconstruction-engine)
8. [Search and Query Engine](#8-search-and-query-engine)
9. [API Layer](#9-api-layer)
10. [Frontend Interface Layer](#10-frontend-interface-layer)
11. [Evidence Bundle Structure](#11-evidence-bundle-structure)
12. [Artifact Database Structure](#12-artifact-database-structure)
13. [Evidence Verification Process](#13-evidence-verification-process)
14. [Report Generation System](#14-report-generation-system)

---

## 1. System Overview

XTRACTR is a digital forensics platform that extracts, parses, verifies, and reports on mobile device evidence. The system operates as a deterministic pipeline where raw device data enters at one end and a cryptographically sealed evidence bundle exits at the other.

The pipeline executes in seven sequential phases:

```
┌─────────┐    ┌─────────┐    ┌──────┐    ┌─────────────┐    ┌─────────┐    ┌────────┐     ┌────────┐
│  INIT   │──▶│ INGEST  │───▶│ SCAN │──▶│ RUN-PLUGINS │───▶│ PROCESS │──▶│ REPORT │ ───▶│ EXPORT │
└─────────┘    └─────────┘    └──────┘    └─────────────┘    └─────────┘    └────────┘     └────────┘
 Create case   Link evidence  Baseline    Parse artifacts    Timeline +     HTML report   Sealed ZIP
 + keys        source         hashing     from raw DBs       Correlation    generation    bundle
```

Each phase is invoked via the CLI entry point (`main.py`) as a subcommand:

| Command        | Description                                         |
|----------------|-----------------------------------------------------|
| `init`         | Create a new case directory, generate Ed25519 identity keys, initialize the SQLite case database, and log the tool environment hash. |
| `ingest`       | Link an evidence source (directory, archive, or disk image) to the case. |
| `scan`         | Walk the evidence source through the Virtual Filesystem (VFS), compute SHA-256 hashes for every file, and store the baseline fingerprint. |
| `run-plugins`  | Execute all artifact parser plugins in process-isolated sandboxes against the evidence. |
| `process`      | Build a unified forensic timeline and run correlation analysis across all parsed artifacts. |
| `report`       | Generate a self-contained HTML evidence report with interactive tables, search, and sorting. |
| `export`       | Perform TOCTOU verification, compute Merkle roots, sign the cryptographic seal, and package the final evidence bundle as a ZIP archive. |

Every phase writes an immutable, hash-chained custody event to the evidence ledger. No custody event can be written after the final seal is computed — any post-seal write would invalidate the sealed `log_root`.

**Entry Point File:** `main.py`  
**Primary Technologies:** Python 3, SQLite3, Ed25519 (via `cryptography` library), SHA-256, Merkle Trees, RFC 3161 TSA

---

## 2. Evidence Acquisition Layer

### What It Does

The Evidence Acquisition Layer is the system's ingestion boundary. It accepts raw forensic data from external sources and presents it to the rest of the pipeline through a uniform, read-only Virtual Filesystem (VFS) abstraction. This layer guarantees that the original evidence is never modified.

### Virtual Filesystem (VFS) Architecture

The VFS is an abstract interface (`core/vfs/base.py`) that provides a consistent file-access API regardless of the physical evidence format. Three concrete backends implement this interface:

| Backend         | Class          | File                    | Supported Formats                       |
|-----------------|----------------|-------------------------|-----------------------------------------|
| Directory VFS   | `DirectoryVFS` | `core/vfs/directory.py` | Extracted filesystem dumps (folders)    |
| Archive VFS     | `ArchiveVFS`   | `core/vfs/archive.py`   | ZIP and TAR archives                    |
| Disk Image VFS  | `TskVFS`       | `core/vfs/tsk.py`       | Raw images (`.dd`, `.raw`, `.img`, `.e01`) via The Sleuth Kit |

**VFS Operations (all read-only):**

| Method        | Purpose                                                    |
|---------------|------------------------------------------------------------|
| `listdir()`   | List contents of a directory in the evidence.              |
| `is_file()`   | Check if a path points to a file.                          |
| `is_dir()`    | Check if a path points to a directory.                     |
| `open()`      | Open a file for reading. Enforces read-only mode.          |
| `stat()`      | Return file metadata: size, mtime, ctime, mode.           |
| `walk()`      | Recursive directory walk, yields `(root, dirs, files)`.    |
| `read_bytes()`| Read raw bytes from a file with optional size limit.       |

**Factory Function:** `core/ingest.py` → `get_vfs(source_path)`

This function inspects the source path and returns the correct VFS backend:

1. If the path is a directory → `DirectoryVFS`
2. If the path is a ZIP or TAR archive → `ArchiveVFS`
3. If the path extension matches `.dd`, `.raw`, `.img`, or `.e01` → `TskVFS`
4. Otherwise → raises `ValueError` (unsupported evidence type)

### Measured Boot

Immediately after case initialization, the system computes a Merkle root hash of all Python source files across `core/`, `orchestrator/`, and `plugins/` directories. This hash is recorded as the first custody event (`ENVIRONMENT_HASH`), proving the exact tool version used for the forensic acquisition.

**File:** `core/environment.py` → `log_environment()`

### Baseline Creation

After ingestion, the `scan` command walks the VFS and computes SHA-256 hashes for every file in the evidence source. These hashes are stored in the `baseline_files` table of the case database. This baseline serves as the ground truth for later TOCTOU (Time-of-Check-Time-of-Use) verification.

**File:** `core/baseline.py` → `create_baseline(vfs, db)`

The baseline also supports drift detection via `check_drift(vfs, db)`, which compares the current VFS state against the stored baseline and reports modified, missing, or new files.

---

## 3. Artifact Parsing Layer

### What It Does

The Artifact Parsing Layer converts raw device databases and files into structured forensic artifacts. Each artifact type (SMS messages, call logs, browser history, etc.) is handled by a dedicated parser plugin.

### Plugin Architecture

All plugins inherit from `BasePlugin` (`core/plugin_interface.py`) and must implement two abstract methods:

| Method       | Purpose                                                                     |
|--------------|-----------------------------------------------------------------------------|
| `can_parse(vfs)` | Quick check (file existence, database presence) to determine if the plugin is applicable to the evidence. |
| `parse(vfs, context)` | Extract artifacts from the evidence source. Returns a list of `Artifact` objects. |

Every plugin declares metadata constants:

```
NAME        = "SMS Parser"
VERSION     = "1.1.0"
DESCRIPTION = "Extracts SMS/MMS from Android mmssms.db"
AUTHOR      = "XtractR Core"
DEPENDENCIES = []
```

### Standardized Artifact Format

All plugins return `Artifact` dataclass instances (`core/plugin_interface.py`):

| Field             | Type             | Description                                    |
|-------------------|------------------|------------------------------------------------|
| `artifact_id`     | `str`            | Unique identifier for this artifact instance.  |
| `artifact_type`   | `str`            | Category (e.g., `SMS`, `CALL_LOG`, `CHROME_HISTORY`). |
| `source_path`     | `str`            | Path within the VFS where the source data was found. |
| `timestamp_utc`   | `int`            | Unix epoch in milliseconds (UTC).              |
| `parser_name`     | `str`            | Name of the plugin that produced this artifact.|
| `parser_version`  | `str`            | Semantic version of the plugin.                |
| `actor`           | `str`            | Entity associated (phone number, email, or `DEVICE`). |
| `details`         | `Dict[str, Any]` | The actual parsed content (message body, call duration, URL, etc.). |
| `reference_hash`  | `Optional[str]`  | SHA-256 hash of the source file.               |
| `confidence`      | `float`          | Confidence score (0.0–1.0).                    |

### Registered Plugins

| Plugin File                | Class                  | Artifact Type(s)          | Data Source                        |
|---------------------------|------------------------|---------------------------|------------------------------------|
| `sms_parser.py`           | `SMSParser`            | `SMS`, `MMS`              | `mmssms.db` (Android)              |
| `calllog_parser.py`       | `CallLogParser`        | `CALL_LOG`                | `calllog.db` / `contacts2.db`     |
| `contacts_parser.py`      | `ContactsParser`       | `CONTACT`                 | `contacts2.db`                    |
| `chrome_history_parser.py`| `ChromeHistoryParser`  | `CHROME_HISTORY`, `CHROME_DOWNLOAD` | `History` (Chrome SQLite)  |
| `email_parser.py`         | `EmailParser`          | `EMAIL`                   | `EmailProvider.db`, `.eml` files  |
| `installed_apps_parser.py`| `InstalledAppsParser`  | `INSTALLED_APP`           | `packages.xml`, `packages.list`   |
| `accounts_parser.py`      | `AccountsParser`       | `ACCOUNT`                 | `accounts.db`                     |
| `media_scanner.py`        | `MediaScanner`         | `MEDIA_IMAGE`, `MEDIA_VIDEO`, `MEDIA_AUDIO` | File system scan with EXIF metadata extraction |
| `location_parser.py`      | `LocationParser`       | `LOCATION`                | Various GPS/location databases     |
| `whatsapp_parser.py`      | `WhatsAppParser`       | `WHATSAPP_MESSAGE`        | `msgstore.db`                     |
| `whatsapp_detector.py`    | `WhatsAppDetector`     | `WHATSAPP_PRESENCE`       | WhatsApp directory detection       |
| `telegram_parser.py`      | `TelegramParser`       | `TELEGRAM_MESSAGE`        | `cache4.db`                       |
| `instagram_parser.py`     | `InstagramParser`      | `INSTAGRAM_DM`            | Instagram databases                |

### Process Isolation

The Plugin Engine (`core/plugin_engine.py`) executes each plugin in a **separate OS process** via `ProcessPoolExecutor`. This provides:

| Resource Limit        | Value       | Purpose                                     |
|-----------------------|-------------|----------------------------------------------|
| Memory cap            | 512 MB      | `RLIMIT_AS` — prevents a malformed database from consuming all system RAM. |
| CPU time cap          | 30 seconds  | `RLIMIT_CPU` — prevents infinite loops in parsers. |
| Wall-clock timeout    | 45 seconds  | Allows for I/O wait beyond the CPU cap.      |
| Artifact count limit  | 100,000     | Per-plugin cap to prevent output flooding.   |
| Output size limit     | 100 MB      | Cumulative artifact detail size.             |

The engine discovers plugins by scanning the `plugins/` directory for classes that inherit from `BasePlugin`. Plugins are sorted alphabetically (`INV-002: deterministic ordering`) so that execution order is reproducible across runs.

Each plugin's source file is hashed (SHA-256) before execution. This hash is recorded in the `plugin_runs` table, establishing provenance — the exact parser code that produced each artifact is permanently linked to the artifact.

---

## 4. Evidence Storage Layer

### What It Does

The Evidence Storage Layer persists all forensic data — parsed artifacts, custody events, baseline hashes, plugin metadata, and audit seals — in a single SQLite database file.

### Database File

**File:** `case.db` (located in the case directory root)  
**Technology:** SQLite 3 with `row_factory = sqlite3.Row` for named column access  
**Managed by:** `core/database.py` → `CaseDatabase` class

SQLite was chosen because:

1. The entire case database is a single portable file.
2. No external database server is required for field deployment.
3. SQLite is a widely adopted, well-documented storage format.
4. ACID compliance ensures write consistency.

### Database Tables

The schema (`SCHEMA_SQL` in `core/database.py`) defines 8 tables:

| Table                | Purpose                                                             |
|----------------------|---------------------------------------------------------------------|
| `case_metadata`      | Key-value store for case-level settings (case ID, source path, investigator name, tool environment hash). |
| `investigator_profile` | Investigator identity (name, agency, public key PEM, creation timestamp). |
| `custody_events`     | Immutable, hash-chained audit log of all forensic actions.          |
| `baseline_files`     | SHA-256 fingerprints of every file in the original evidence source. |
| `derived_artifacts`  | All parsed artifacts produced by plugins.                           |
| `plugin_registry`    | Registered plugins with name, version, description, and enabled status. |
| `plugin_runs`        | Execution records: which plugin ran, when, how many artifacts it produced, and the plugin's source hash. |
| `audit_seals`        | Cryptographic seals — Merkle roots and Ed25519 signatures for ledger, evidence, and report. |

### Parallel JSONL Ledger

In addition to the SQLite `custody_events` table, every custody event is simultaneously written to an append-only JSONL (JSON Lines) file:

**File:** `case_custody_ledger.jsonl` (same directory as `case.db`)

Each line is a JSON object with the same fields as the `custody_events` table. The JSONL file uses `sort_keys=True` and compact separators for canonical serialization. After every write, `flush()` and `os.fsync()` are called to guarantee the data reaches the physical disk.

This dual-write design provides:

1. **Redundancy:** If the SQLite file is corrupted, the JSONL file preserves the complete custody chain.
2. **Tamper detection:** The JSONL and SQLite records are cross-validated during verification.
3. **Simplicity:** JSONL files can be inspected with any text editor or command-line tool (`cat`, `jq`).

---

## 5. Evidence Integrity Layer

### What It Does

The Evidence Integrity Layer provides cryptographic guarantees that forensic artifacts were not modified after creation. It operates at three levels: individual file hashing, Merkle tree aggregation, and digital signature sealing.

### Hashing

**File:** `core/integrity.py`  
**Algorithm:** SHA-256 (exclusively)

| Function            | Purpose                                                          |
|---------------------|------------------------------------------------------------------|
| `hash_file(file_obj)` | Computes SHA-256 of a file-like object in 64 KB chunks.        |
| `hash_artifact(artifact_dict)` | Computes SHA-256 of an artifact's canonical JSON form. |
| `canonical_json(obj)` | Deterministic JSON serialization: sorted keys, compact separators, ASCII encoding. All hashed JSON passes through this function to guarantee identical byte output for identical logical content. |

### Merkle Trees

Merkle trees aggregate many individual hashes into a single root hash. If any input hash changes, the root changes.

**Function:** `compute_merkle_root(hashes)`

Process:
1. Sort all input hashes alphabetically (determinism).
2. Build a binary tree: pair hashes, concatenate each pair, SHA-256 the concatenation.
3. If the number of leaves is odd, duplicate the last leaf.
4. Repeat until a single root hash remains.
5. If the input list is empty, return `SHA256("EMPTY")`.

### System Root

The system root is the top-level integrity hash for the entire case:

```
system_root = SHA256(artifact_root || log_root)
```

Where:
- `artifact_root` = Merkle root of all derived artifact hashes
- `log_root` = Merkle root of all custody event hashes

**Function:** `compute_system_root(artifact_root, log_root)`

### Ed25519 Digital Signatures

**File:** `core/crypto.py` → `IdentityManager` class  
**Algorithm:** Ed25519 (via `cryptography.hazmat.primitives.asymmetric.ed25519`)

The `IdentityManager` handles:

| Operation                    | Description                                                    |
|------------------------------|----------------------------------------------------------------|
| Key generation               | Ed25519 private/public key pair, stored as PEM files in `keys/` directory. |
| Key encryption               | Private keys are encrypted on disk using `BestAvailableEncryption` with a user-supplied passphrase. |
| X.509 certificate generation | Self-signed certificate binding the Ed25519 key to the investigator's identity (name, organization). |
| Data signing                 | `sign_data(data: bytes) → bytes` — signs arbitrary bytes with the private key. |
| Signature verification       | `verify_signature(signature, data) → bool` — verifies a signature against the public key. |
| Public key fingerprint       | `SHA256(public_key_DER_bytes)` — unique identifier for the investigator's key. |

**Key Files:**

| File                    | Content                                     |
|-------------------------|---------------------------------------------|
| `keys/private_key.pem`  | Ed25519 private key (passphrase-encrypted).  |
| `keys/public_key.pem`   | Ed25519 public key (plaintext PEM).          |
| `keys/certificate.pem`  | Self-signed X.509 certificate (optional).    |

### RFC 3161 Time Stamp Authority (TSA)

**File:** `core/tsa.py` → `TSAClient` class  
**Protocol:** RFC 3161 Time Stamp Protocol  
**Default TSA URL:** `https://freetsa.org/tsr`

The TSA provides externally verifiable timestamps that prevent OS clock manipulation. During export, the system sends a SHA-256 digest to the TSA and receives a signed timestamp token (DER-encoded ASN.1). This token is saved as `seal_tsa.tsr` in the case directory and included in the export bundle.

If the TSA is unreachable, the system operates in **degraded mode** — local timestamps only, with a custody event logged (`TSA_DEGRADED`).

---

## 6. Evidence Ledger

### What It Does

The Evidence Ledger is a tamper-resistant logging system that records every forensic action performed on a case. It uses a Merkle hash chain where each event references the hash of the previous event, creating an unbreakable sequence.

### How It Works

**File:** `core/database.py` → `CaseDatabase.log_event()`

When a custody event is logged:

1. The system reads the `this_event_hash` of the most recent event from the `custody_events` table (or uses `GENESIS_HASH_00000000000000000000000000000000` for the first event).
2. A canonical payload string is constructed: `"{timestamp}|{action}|{details}|{source_hash}|{prev_hash}|{actor}"`
3. The payload is encoded to UTF-8 and hashed with SHA-256 to produce `this_event_hash`.
4. The event is inserted into both the SQLite `custody_events` table and the JSONL append-only ledger file.
5. The JSONL write is followed by `flush()` and `os.fsync()` to ensure durability.

### Custody Event Fields

| Field              | Type    | Description                                              |
|--------------------|---------|----------------------------------------------------------|
| `id`               | `int`   | Auto-incrementing primary key.                            |
| `timestamp_utc`    | `int`   | Unix epoch in milliseconds (UTC).                         |
| `action`           | `str`   | Event type (e.g., `CASE_INIT`, `EVIDENCE_ACQUIRED`, `BASELINE_COMPLETE`, `PLUGIN_COMPLETED`, `PROCESSING_COMPLETE`, `REPORT_GENERATED`, `TOCTOU_VERIFIED`, `TSA_ANCHORED`). |
| `details`          | `str`   | Human-readable description of the event.                  |
| `source_hash`      | `str`   | SHA-256 hash of the relevant source data (or `N/A`).     |
| `prev_event_hash`  | `str`   | SHA-256 hash of the preceding event (Merkle link).       |
| `this_event_hash`  | `str`   | SHA-256 hash of this event's canonical payload.           |
| `actor`            | `str`   | Who triggered the event (`USER`, `SYSTEM`, plugin name). |

### Chain Integrity Verification

**File:** `core/integrity.py` → `verify_ledger_integrity(db_path)`

Verification walks every event in order and checks:
1. That each event's `prev_event_hash` matches the `this_event_hash` of the preceding event.
2. That each event's `this_event_hash` can be recomputed from its payload fields.

If either check fails, the ledger has been tampered with.

### JSONL Cross-Validation

**File:** `xtractr_verify.py` → `verify_jsonl_ledger(case_dir, db_path)`

The independent verifier compares every field in the JSONL ledger against the corresponding SQLite row. Any mismatch between the two storage systems indicates tampering.

---

## 7. Timeline Reconstruction Engine

### What It Does

The Timeline Reconstruction Engine aggregates artifacts from all parser plugins into a single, chronologically ordered timeline. This allows investigators to see all device activity — messages, calls, web browsing, app usage, location changes — in temporal sequence.

### How It Works

**File:** `core/timeline.py` → `TimelineEngine` class

1. Query all rows from the `derived_artifacts` table, ordered by `timestamp_utc ASC`.
2. Parse each artifact's `details` field from its JSON string representation.
3. Build a list of timeline event objects with fields: `timestamp`, `type`, `actor`, `details`, `source`, `plugin`.
4. Apply a deterministic sort with a full tie-breaker chain (`INV-002`): `(timestamp, type, source, actor)`.
5. Write the timeline in two formats:
   - `timeline.json` — full event data with proper JSON types and indentation.
   - `timeline.csv` — tabular format with columns: `Timestamp (UTC)`, `Type`, `Actor`, `Details`, `Source`, `Plugin`. Details are truncated to 500 characters for CSV.

### Correlation Engine

**File:** `core/correlation.py` → `CorrelationEngine` class

After the timeline is built, the Correlation Engine analyzes artifacts for behavioral patterns:

| Analysis             | Description                                                  |
|----------------------|--------------------------------------------------------------|
| Top Actors           | Identifies the 10 most frequently communicating entities (phone numbers, emails) across SMS, call log, and contact artifacts. |
| Activity Heatmap     | Counts artifact events by hour of day (UTC 0–23), showing when the device was most active. |
| Suspicious Gaps      | Reserved for detection of unusual periods of inactivity.      |

---

## 8. Search and Query Engine

### What It Does

The Search and Query Engine allows investigators to filter and navigate large artifact datasets interactively. It operates at two levels: backend SQL queries and frontend JavaScript filtering.

### Backend Queries

All artifact data is stored in the `derived_artifacts` table in SQLite. The report generator (`core/reporting/generator.py`) queries this table by artifact type:

```sql
SELECT * FROM derived_artifacts
WHERE artifact_type = ?
ORDER BY timestamp_utc ASC
```

Artifact types can be queried individually (e.g., `SMS`) or as groups (e.g., `['WHATSAPP_MESSAGE', 'WHATSAPP_PRESENCE']`).

The timeline engine queries across all artifact types simultaneously and applies deterministic sorting.

### Frontend Search

**File:** `core/reporting/template.py` → `JS` constant

The HTML report includes a client-side search engine implemented in JavaScript:

| Feature           | Description                                                      |
|-------------------|------------------------------------------------------------------|
| Table filtering   | A search input on each artifact page filters table rows by text content. The filter is case-insensitive and matches against all visible columns. |
| Column sorting    | Clickable column headers sort the table. Sort direction toggles between ascending and descending. A visual arrow indicator (▲/▼) shows the current sort state. |
| Pagination        | Tables display 50 rows per page with Previous/Next controls. The page count updates dynamically after filtering. |
| CSV export        | Each table can be exported to a CSV file directly from the browser. The export captures all visible columns and all rows (not just the current page). |

---

## 9. API Layer

### What It Does

The API Layer exposes artifact data from the SQLite database to the frontend report. In XTRACTR's architecture, this is a build-time data injection layer rather than a live REST API — the report generator reads all data from the database at report generation time and embeds it directly in the HTML output.

### Data Flow

```
case.db (SQLite) ──▶ generator.py (Python queries) ──▶ report.html (static HTML with embedded data)
```

**File:** `core/reporting/generator.py` → `generate_report(db, output_dir)`

The generator function:

1. Opens a cursor on the case database.
2. Executes typed queries for each artifact category: SMS, call logs, contacts, web history, media, apps, WhatsApp, Telegram, Instagram, email, location, accounts.
3. For each category, retrieves rows from `derived_artifacts` filtered by `artifact_type`.
4. Parses the `details` JSON column of each row.
5. Formats each row into an HTML table row using template helper functions.
6. Assembles the complete HTML document with embedded CSS and JavaScript.
7. Writes the result to `report.html` in the case directory.

### Helper Functions

| Function               | Purpose                                             |
|------------------------|-----------------------------------------------------|
| `fetch_by_type(atype)` | Query `derived_artifacts` for a single artifact type. |
| `fetch_by_types(atypes)` | Query for multiple artifact types simultaneously. |
| `get_count(table)`     | Count rows in any database table.                   |
| `safe_parse(d)`        | Safely parse a JSON `details` string, returning empty dict on failure. |
| `ts_fmt(ts_ms)`        | Convert Unix epoch milliseconds to human-readable `YYYY-MM-DD HH:MM:SS UTC`. |
| `esc(s)`               | HTML-escape a string to prevent XSS.                |
| `badge(text, style)`   | Generate an HTML badge element (e.g., `SENT`, `RECEIVED`, `MISSED`). |

---

## 10. Frontend Interface Layer

### What It Does

The Frontend Interface Layer is the visual output of XTRACTR. It presents forensic artifacts in a professional SaaS-style dashboard that investigators can browse, search, filter, and export.

### Technology

The frontend is a **self-contained static HTML file** (`report.html`). It requires no web server, no JavaScript framework, and no external dependencies beyond Google Fonts. The entire report — CSS, JavaScript, and data — is embedded in a single file that opens in any modern browser.

**Files:**
- `core/reporting/template.py` — CSS design system, JavaScript logic, and HTML helper functions.
- `core/reporting/generator.py` — Data assembly and HTML construction.

### Layout Structure

```
┌────────────────────────────────────────────────────┐
│  TOP NAVIGATION BAR (fixed)                        │
│  Logo │ Case ID │ Investigator │ Export Controls    │
├──────────┬─────────────────────────────────────────┤
│          │  CONTEXT HEADER                         │
│  LEFT    │  Page Title │ Artifact Count │ Search   │
│  SIDEBAR │─────────────────────────────────────────│
│          │                                         │
│  Nav:    │  DATA TABLE                             │
│  Overview│  Sortable columns │ Paginated rows      │
│  SMS     │  Badge indicators │ Monospace hashes    │
│  Calls   │                                         │
│  Contacts│                                         │
│  Web     │─────────────────────────────────────────│
│  Media   │  PAGINATION                             │
│  Apps    │  ◀ Page 1 of N ▶                        │
│  ...     │                                         │
│  Timeline│                                         │
│  Ledger  │                                         │
└──────────┴─────────────────────────────────────────┘
```

### Design System

| Token                  | Value                           | Purpose                    |
|------------------------|---------------------------------|----------------------------|
| Primary Background     | `#0d1117`                       | Near-black surface         |
| Surface Background     | `#161b22`                       | Card/panel background      |
| Elevated Background    | `#1c2128`                       | Table header, sticky nav   |
| Accent Color           | `#58a6ff`                       | Interactive elements, links|
| Text Primary           | `#e6edf3`                       | Main body text             |
| Text Muted             | `#7d8590`                       | Secondary labels           |
| Font Stack             | `Inter, system-ui, sans-serif`  | Body text                  |
| Monospace Font         | `'SF Mono', Consolas, monospace`| Hashes, technical values   |
| Border Radius          | `6px`                           | Cards, inputs, buttons     |

### Artifact Pages

Each artifact type gets its own page in the dashboard:

| Page       | Table Columns                                               |
|------------|-------------------------------------------------------------|
| SMS        | Timestamp, Direction (badge), Address, Body, Read Status    |
| Calls      | Timestamp, Type (badge), Number, Duration, Data Usage       |
| Contacts   | Name, Phone, Email, Organization                            |
| Web History| Timestamp, Title, URL, Visit Count, Typed Count             |
| Media      | Preview Thumbnail, Filename, MIME Type, Size, EXIF Data     |
| Apps       | App Name, Package, Version, Installed Date, Source          |
| WhatsApp   | Timestamp, Sender, Message, Media Type, Status              |
| Telegram   | Timestamp, Chat, Sender, Message, Media                     |
| Instagram  | Timestamp, Thread, Sender, Message                          |
| Email      | Timestamp, From, To, Subject, Snippet                       |
| Location   | Timestamp, Latitude, Longitude, Provider, Accuracy          |
| Accounts   | Service, Username, Email, Display Name                      |
| Timeline   | Timestamp, Type (badge), Actor, Details, Source, Plugin     |
| Ledger     | Timestamp, Action, Details, Source Hash, Event Hash, Actor  |

---

## 11. Evidence Bundle Structure

### What It Is

The evidence bundle is the final output of the XTRACTR pipeline. It is a ZIP archive containing all forensic artifacts, integrity proofs, cryptographic signatures, and the human-readable report. This bundle serves as the verified, sealed forensic output for review and analysis.

### Bundle Creation Process

**File:** `core/export.py` → `ExportManager.create_bundle()`

The export process executes six steps in strict order:

1. **TOCTOU Guard:** Re-hash every original evidence file and compare against the stored baseline. If any file has been modified since the `scan` phase, abort with exit code 10.
2. **TSA Anchoring:** Request an RFC 3161 timestamp from the external TSA before computing Merkle roots. This proves the bundle creation window.
3. **Merkle Computation:** Compute evidence root, artifact root, and log root from the database. Combine artifact root and log root into the system root.
4. **Seal Signing:** Build the signed payload (all roots, case metadata, parser manifest, tool version), serialize it to canonical JSON, sign with Ed25519, and write `seal.json`.
5. **File Signing:** Generate Ed25519 `.sig` files for `seal.json`, `case.db`, `report.html`, `manifest.json`, and the JSONL ledger.
6. **ZIP Packaging:** Build the manifest (SHA-256 hashes of all included files), sign the manifest, and package everything into a compressed ZIP archive.

### Directory Tree

```
case_bundle/
├── manifest.json              # File inventory with SHA-256 hashes
├── manifest.json.sig          # Ed25519 signature of manifest.json
├── seal.json                  # Cryptographic seal (Merkle roots + signature)
├── seal.json.sig              # Ed25519 signature of seal.json
├── case.db                    # SQLite database (all artifacts + ledger)
├── case.db.sig                # Ed25519 signature of case.db
├── case_custody_ledger.jsonl  # Append-only JSONL custody log
├── case_custody_ledger.jsonl.sig  # Ed25519 signature of JSONL ledger
├── report.html                # Self-contained HTML forensic report
├── report.html.sig            # Ed25519 signature of report.html
├── timeline.json              # Unified timeline (JSON)
├── timeline.csv               # Unified timeline (CSV)
├── investigator.pub           # Ed25519 public key (PEM)
├── investigator.crt           # X.509 self-signed certificate (PEM, optional)
└── seal_tsa.tsr               # RFC 3161 TSA timestamp token (optional)
```

### File Descriptions

#### `manifest.json`

| Field        | Content                                                          |
|--------------|------------------------------------------------------------------|
| `case_id`    | The case identifier set during `init`.                           |
| `created_at` | Unix epoch in milliseconds when the manifest was generated.      |
| `files`      | Dictionary mapping each filename to its SHA-256 hash.            |

**Generated by:** `ExportManager.create_bundle()` step 6.  
**Used by:** The verifier checks that every file in the bundle matches its declared hash.

#### `seal.json`

| Field                       | Content                                                    |
|-----------------------------|------------------------------------------------------------|
| `system_root`               | SHA-256 of `artifact_root || log_root`.                    |
| `artifact_root`             | Merkle root of all derived artifact hashes.                |
| `log_root`                  | Merkle root of all custody event hashes.                   |
| `evidence_root`             | Merkle root of all baseline file hashes.                   |
| `case_id`                   | Case identifier.                                           |
| `execution_id`              | Plugin execution batch identifier.                         |
| `investigator_fingerprint`  | SHA-256 of the investigator's public key DER bytes.        |
| `parser_version_manifest`   | Map of plugin name → source file SHA-256 hash.             |
| `schema_version`            | Database schema version (`3.0.0`).                         |
| `tool_version`              | XTRACTR tool version (`1.1.0`).                            |
| `build_hash`                | SHA-256 of the canonical parser version manifest.          |
| `timestamp_utc`             | Seal creation timestamp (Unix ms).                         |
| `artifact_count`            | Total number of derived artifacts sealed.                  |
| `log_entry_count`           | Total number of custody events sealed.                     |
| `baseline_file_count`       | Total number of baseline evidence files sealed.            |
| `algorithm`                 | Hash algorithm used (`SHA256`).                            |
| `signature`                 | Base64-encoded Ed25519 signature of the canonical JSON payload (all fields except `signature` itself). |

**Generated by:** `ExportManager.create_bundle()` step 4.  
**Used by:** The verifier recomputes all Merkle roots from the database and checks the signature.

#### `case.db`

The SQLite database containing all parsed artifacts, custody events, baseline hashes, plugin run records, and case metadata. This is the authoritative data store for the entire case.

**Generated by:** `CaseDatabase` class throughout the pipeline.  
**Used by:** The report generator, timeline engine, verifier, and any third-party tool that can read SQLite.

#### `case_custody_ledger.jsonl`

Append-only JSON Lines file. Each line is a single custody event serialized with sorted keys and compact separators. Serves as a redundant, human-readable copy of the `custody_events` table.

**Generated by:** `CaseDatabase.log_event()` dual-write.  
**Used by:** The verifier cross-validates every JSONL line against the corresponding SQLite row.

#### `report.html`

Self-contained HTML forensic report. Opens in any browser. Contains all CSS, JavaScript, and artifact data inline. No external dependencies.

**Generated by:** `core/reporting/generator.py` → `generate_report()`.  
**Used by:** Investigators and reviewers for visual examination of evidence.

#### `timeline.json` / `timeline.csv`

Unified chronological timeline of all forensic artifacts in machine-readable (JSON) and human-readable (CSV) formats.

**Generated by:** `core/timeline.py` → `TimelineEngine.build_timeline()`.  
**Used by:** External analysis tools, spreadsheet applications, or the report's Timeline page.

#### `investigator.pub`

The Ed25519 public key of the investigator who produced this bundle. Required for signature verification.

**Generated by:** Copied from `keys/public_key.pem` during export.  
**Used by:** The verifier uses this key to verify all `.sig` files and the `seal.json` signature.

#### `investigator.crt`

Self-signed X.509 certificate binding the Ed25519 public key to the investigator's identity (common name, organization). Optional.

**Generated by:** `IdentityManager._generate_self_signed_cert()`.  
**Used by:** PKI verification, organizational identity confirmation.

#### `seal_tsa.tsr`

DER-encoded RFC 3161 timestamp token from an external timestamp authority. Proves the bundle was created within a specific time window, independent of the local system clock. Optional — only present if the TSA was reachable during export.

**Generated by:** `TSAClient.request_timestamp()`.  
**Used by:** Auditors and reviewers for independent time verification.

#### `.sig` Files

Each `.sig` file contains the hex-encoded Ed25519 signature of the corresponding data file. The signature is computed over the raw bytes of the file.

**Generated by:** `ExportManager._sign_file(filename)`.  
**Used by:** The verifier reads the `.sig` file, loads the public key, and calls `verify_signature()`.

---

## 12. Artifact Database Structure

### Schema Location

**File:** `core/database.py` → `SCHEMA_SQL` constant

All parsed artifacts are stored in the `derived_artifacts` table. The `details` column holds a JSON-encoded string containing the full parsed data for each artifact. The following sections describe the logical structure of each artifact type as it appears within the `details` JSON.

### Artifact Tables (Logical Views)

#### `sms_messages`

Extracted from Android `mmssms.db`. Parser: `sms_parser.py`.

| Field        | Type     | Description                                     |
|--------------|----------|-------------------------------------------------|
| `artifact_id`| `str`   | Unique hash-based ID (`sms_{hash}`).             |
| `timestamp_utc` | `int` | Message timestamp (Unix ms).                    |
| `actor`      | `str`    | Phone number of the other party.                |
| `body`       | `str`    | Message text content.                            |
| `direction`  | `str`    | `SENT` or `RECEIVED` (derived from `type` field). |
| `read`       | `bool`   | Whether the message was read.                   |
| `source_path`| `str`    | VFS path to `mmssms.db`.                        |

#### `call_logs`

Extracted from `calllog.db` or `contacts2.db`. Parser: `calllog_parser.py`.

| Field         | Type     | Description                                    |
|---------------|----------|------------------------------------------------|
| `artifact_id` | `str`    | Unique identifier.                             |
| `timestamp_utc` | `int`  | Call start timestamp (Unix ms).                |
| `actor`       | `str`    | Phone number.                                  |
| `type`        | `str`    | `INCOMING`, `OUTGOING`, `MISSED`, `VOICEMAIL`, `REJECTED`, `BLOCKED`. |
| `duration`    | `int`    | Call duration in seconds.                       |
| `data_usage`  | `int`    | Data usage in bytes (for VoIP calls).           |
| `source_path` | `str`    | VFS path to the call log database.             |

#### `contacts`

Extracted from `contacts2.db`. Parser: `contacts_parser.py`.

| Field          | Type     | Description                                   |
|----------------|----------|-----------------------------------------------|
| `artifact_id`  | `str`    | Unique identifier.                            |
| `name`         | `str`    | Contact display name.                         |
| `phone`        | `str`    | Phone number.                                 |
| `email`        | `str`    | Email address.                                |
| `organization` | `str`    | Company or organization name.                 |
| `source_path`  | `str`    | VFS path to `contacts2.db`.                   |

#### `web_history`

Extracted from Chrome's `History` SQLite database. Parser: `chrome_history_parser.py`.

| Field          | Type     | Description                                   |
|----------------|----------|-----------------------------------------------|
| `artifact_id`  | `str`    | Unique identifier.                            |
| `timestamp_utc`| `int`    | Visit timestamp (Unix ms).                    |
| `url`          | `str`    | Full URL visited.                             |
| `title`        | `str`    | Page title.                                   |
| `visit_count`  | `int`    | Total number of visits to this URL.           |
| `typed_count`  | `int`    | Number of times the URL was manually typed.   |
| `source_path`  | `str`    | VFS path to Chrome `History` file.            |

#### `media_files`

Extracted by filesystem scan with EXIF metadata extraction. Parser: `media_scanner.py`.

| Field          | Type     | Description                                   |
|----------------|----------|-----------------------------------------------|
| `artifact_id`  | `str`    | Unique identifier.                            |
| `timestamp_utc`| `int`    | File modification timestamp or EXIF date.     |
| `filename`     | `str`    | Original filename.                            |
| `mime_type`    | `str`    | MIME type (e.g., `image/jpeg`, `video/mp4`).  |
| `size`         | `int`    | File size in bytes.                           |
| `exif`         | `dict`   | EXIF metadata (GPS coordinates, camera model, dimensions, etc.). |
| `sha256`       | `str`    | SHA-256 hash of the media file.               |
| `source_path`  | `str`    | VFS path to the media file.                   |

#### `installed_apps`

Extracted from `packages.xml` or `packages.list`. Parser: `installed_apps_parser.py`.

| Field           | Type     | Description                                  |
|-----------------|----------|----------------------------------------------|
| `artifact_id`   | `str`    | Unique identifier.                           |
| `app_name`      | `str`    | Application display name.                    |
| `package_name`  | `str`    | Android package identifier (e.g., `com.whatsapp`). |
| `version`       | `str`    | Installed version string.                    |
| `install_date`  | `int`    | Installation timestamp (Unix ms).            |
| `source`        | `str`    | Installation source (e.g., `Play Store`).    |
| `source_path`   | `str`    | VFS path to packages file.                   |

#### `accounts`

Extracted from `accounts.db`. Parser: `accounts_parser.py`.

| Field          | Type     | Description                                   |
|----------------|----------|-----------------------------------------------|
| `artifact_id`  | `str`    | Unique identifier.                            |
| `service`      | `str`    | Account service name (e.g., `com.google`).    |
| `username`     | `str`    | Account username or handle.                   |
| `email`        | `str`    | Associated email address.                     |
| `display_name` | `str`    | User-facing display name.                     |
| `source_path`  | `str`    | VFS path to `accounts.db`.                    |

#### `timeline_events`

Aggregated from all artifact types. Generated by: `core/timeline.py`.

| Field          | Type     | Description                                   |
|----------------|----------|-----------------------------------------------|
| `timestamp`    | `int`    | Event timestamp (Unix ms UTC).                |
| `type`         | `str`    | Artifact type (e.g., `SMS`, `CALL_LOG`).      |
| `actor`        | `str`    | Associated entity.                            |
| `details`      | `dict`   | Parsed artifact content.                      |
| `source`       | `str`    | VFS source path.                              |
| `plugin`       | `str`    | Plugin that produced this artifact.           |

---

## 13. Evidence Verification Process

### What It Does

The Evidence Verification Process independently validates that a sealed evidence bundle has not been tampered with. It is implemented as a standalone Python script (`xtractr_verify.py`, 935 lines) that has no dependency on the core XTRACTR codebase — it duplicates all integrity functions to ensure independence.

### Verification Steps

The verifier executes the following checks in sequence:

#### Step 1: Load and Parse `seal.json`

- Read `seal.json` from the case directory.
- Parse the JSON and extract all fields including the `signature`.
- Normalize types (integers, strings) to prevent type coercion mismatches during canonical serialization.

#### Step 2: SQLite Integrity Check

- Run `PRAGMA integrity_check` on `case.db`.
- If SQLite reports corruption, abort with exit code 1.

#### Step 3: Verify Custody Ledger Chain

- Read all rows from `custody_events` ordered by `id ASC`.
- Starting from `GENESIS_HASH_00000000000000000000000000000000`, verify that:
  - Each event's `prev_event_hash` matches the previous event's `this_event_hash`.
  - Each event's `this_event_hash` can be recomputed from its payload: `SHA256("{timestamp}|{action}|{details}|{source_hash}|{prev_hash}|{actor}")`.
- If any link is broken or any hash mismatches, report `LEDGER_TAMPERED` (exit code 10).

#### Step 4: Cross-Validate JSONL Ledger

- Read the JSONL ledger file (`case_custody_ledger.jsonl`).
- Compare every field of every JSONL entry against the corresponding SQLite row.
- Any field mismatch between the two storage systems indicates tampering (exit code 14).

#### Step 5: Recompute Merkle Roots

- Query `baseline_files` → compute `evidence_root` (Merkle root of evidence file hashes).
- Query `derived_artifacts` → compute `artifact_root` (Merkle root of artifact hashes using canonical JSON).
- Query `custody_events` → compute `log_root` (Merkle root of custody event hashes using canonical JSON).
- Compute `system_root = SHA256(artifact_root || log_root)`.

#### Step 6: Compare Recomputed Roots Against Seal

- Compare each recomputed root (`evidence_root`, `artifact_root`, `log_root`, `system_root`) against the corresponding value in `seal.json`.
- Any mismatch indicates that the database contents have been altered after sealing (exit code 10).

#### Step 7: Verify Count Fields

- Compare `artifact_count`, `log_entry_count`, and `baseline_file_count` in `seal.json` against the actual row counts in the database.
- Mismatches indicate record insertion or deletion.

#### Step 8: Verify Schema and Tool Version

- Check that the `schema_version` and `tool_version` in `seal.json` match expected values.
- Version drift triggers a warning (exit code 13 for critical drift).

#### Step 9: Verify Investigator Fingerprint

- Compute `SHA256(public_key_DER_bytes)` from the provided public key file.
- Compare against `investigator_fingerprint` in `seal.json`.
- Mismatch indicates the seal was signed by a different key than the one presented (exit code 11).

#### Step 10: Verify Ed25519 Signature on Seal

- Reconstruct the signed payload from `seal.json` (all fields except `signature`).
- Serialize to canonical JSON (sorted keys, compact separators, ASCII).
- Decode the Base64 signature from `seal.json`.
- Verify the Ed25519 signature using the provided public key.
- Invalid signature means the seal or its contents have been modified (exit code 11).

#### Step 11: Verify Individual File Signatures

- For each `.sig` file in the bundle (`case.db.sig`, `report.html.sig`, `manifest.json.sig`, JSONL `.sig`):
  - Read the raw bytes of the corresponding data file.
  - Read the hex-encoded signature from the `.sig` file.
  - Verify the Ed25519 signature against the public key.

#### Step 12: Verify Manifest Hashes

- For each file listed in `manifest.json`:
  - Compute SHA-256 of the actual file.
  - Compare against the declared hash in the manifest.
  - Any mismatch means a file was modified after manifest creation.

### Exit Codes

| Code | Meaning                                            |
|------|----------------------------------------------------|
| 0    | All checks passed — bundle integrity verified.     |
| 1    | General verification failure.                      |
| 10   | Merkle root mismatch — data tampered.              |
| 11   | Signature invalid — cryptographic verification failed. |
| 12   | Schema version mismatch.                           |
| 13   | Tool version drift.                                |
| 14   | JSONL/SQLite cross-validation mismatch.            |

### Self-Test Mode

The verifier includes a self-test command (`python xtractr_verify.py self-test`) that cross-checks the verifier's duplicated integrity functions against the `core.integrity` module to ensure they produce identical results.

---

## 14. Report Generation System

### What It Does

The Report Generation System produces a self-contained HTML forensic report that visualizes all parsed artifacts. The report is designed for on-screen examination by investigators and for inclusion in forensic evidence bundles.

### Architecture

The report system is split into two files:

| File                         | Responsibility                                        |
|------------------------------|-------------------------------------------------------|
| `core/reporting/template.py` | Design system (CSS variables, layout styles), interactive JavaScript (search, sort, pagination, CSV export), and HTML helper functions. |
| `core/reporting/generator.py`| Data retrieval from SQLite, artifact formatting, and final HTML assembly. |

### Report Generation Flow

1. Open a database cursor.
2. Count artifacts per type for the statistics overview.
3. For each artifact category, fetch rows from `derived_artifacts`.
4. Parse the `details` JSON column of each row.
5. Format each artifact into an HTML table row using helper functions (`td()`, `td_mono()`, `badge()`).
6. Build navigation sidebar items with artifact counts.
7. Compute integrity data (Merkle roots) for display in the integrity verification banner.
8. Assemble the full HTML document: `<head>` (Google Fonts import, embedded CSS) → `<body>` (topbar, sidebar, main workspace with all artifact pages) → `<script>` (embedded JavaScript).
9. Write to `report.html` in the case directory.
10. Log a `REPORT_GENERATED` custody event.

### Report Sections

| Section           | Content                                                     |
|-------------------|-------------------------------------------------------------|
| Overview/Stats    | Artifact count cards (SMS, Calls, Contacts, Web, Media, etc.) with visual indicators. |
| Integrity Banner  | Evidence root, artifact root, log root, system root displayed as monospace hash strings. |
| Artifact Pages    | One page per artifact type with searchable, sortable, paginated data tables. |
| Timeline Page     | All artifacts in chronological order with type badges.      |
| Ledger Page       | Complete custody event log showing the hash chain.          |

### Print Compatibility

The CSS includes print-specific rules:
- Sidebar and navigation are hidden.
- All pages display sequentially (no tab hiding).
- Search inputs and pagination controls are hidden.
- Content respects `page-break-inside: avoid`.

