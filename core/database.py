import sqlite3
import json
import hashlib
import time
import os
import logging
from typing import Optional, List, Dict, Any
from .time_provider import TimeProvider

logger = logging.getLogger("xtractr.db")

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS case_metadata (
    key TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS investigator_profile (
    id INTEGER PRIMARY KEY,
    name TEXT,
    agency TEXT,
    public_key_pem TEXT,
    created_at INTEGER
);

CREATE TABLE IF NOT EXISTS custody_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_utc INTEGER NOT NULL,
    action TEXT NOT NULL,
    details TEXT,
    source_hash TEXT,
    prev_event_hash TEXT NOT NULL, -- Merkle Link
    this_event_hash TEXT NOT NULL, -- SHA256(timestamp + action + details + source_hash + prev_hash)
    actor TEXT
);

CREATE TABLE IF NOT EXISTS baseline_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    path TEXT NOT NULL,
    size INTEGER,
    mtime INTEGER,
    sha256 TEXT NOT NULL,
    UNIQUE(path)
);

CREATE TABLE IF NOT EXISTS derived_artifacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    execution_id TEXT,
    artifact_type TEXT,
    source_path TEXT,
    output_path TEXT,
    sha256 TEXT,
    plugin_name TEXT,
    plugin_version TEXT,
    timestamp_utc INTEGER,
    details TEXT,
    actor TEXT
);

CREATE TABLE IF NOT EXISTS plugin_registry (
    name TEXT PRIMARY KEY,
    version TEXT,
    description TEXT,
    enabled BOOLEAN DEFAULT 1
);

CREATE TABLE IF NOT EXISTS plugin_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    execution_id TEXT,
    plugin_name TEXT,
    plugin_source_hash TEXT,
    start_time INTEGER,
    end_time INTEGER,
    status TEXT,
    artifacts_count INTEGER,
    error_msg TEXT
);

CREATE TABLE IF NOT EXISTS audit_seals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    seal_type TEXT, -- LEDGER, EVIDENCE, REPORT
    timestamp_utc INTEGER,
    merkle_root TEXT,
    signature_hex TEXT,
    snapshot_json TEXT
);
"""

class CaseDatabase:
    """
    Manages the Case File (SQLite).
    Enforces Chain of Custody via Merkle Hashing.
    Parallel JSONL append-only ledger for immutable storage.
    """
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._conn = sqlite3.connect(self.db_path)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()
        
        # Load last hash for chaining
        self.last_hash = self._get_last_event_hash()

        # Initialize JSONL append-only ledger
        self._ledger_path = os.path.splitext(db_path)[0] + "_custody_ledger.jsonl"
        self._ledger_file = None
        self._init_ledger()

    def _init_schema(self):
        cursor = self._conn.cursor()
        cursor.executescript(SCHEMA_SQL)
        self._conn.commit()

    def _init_ledger(self):
        """Open the append-only JSONL ledger file."""
        try:
            self._ledger_file = open(self._ledger_path, "a", encoding="utf-8")
            logger.info(f"JSONL ledger initialized: {self._ledger_path}")
        except Exception as e:
            logger.warning(f"Could not open JSONL ledger: {e}")
            self._ledger_file = None

    def _get_last_event_hash(self) -> str:
        cursor = self._conn.cursor()
        cursor.execute("SELECT this_event_hash FROM custody_events ORDER BY id DESC LIMIT 1")
        row = cursor.fetchone()
        if row:
            return row["this_event_hash"]
        return "GENESIS_HASH_00000000000000000000000000000000"

    def log_event(self, action: str, details: str, source_hash: str = "N/A", actor: str = "SYSTEM"):
        """
        Log an immutable, chained custody event.
        Writes to BOTH SQLite and the append-only JSONL ledger.
        """
        timestamp = TimeProvider.now_ms()
        prev_hash = self.last_hash
        
        # Compute proper canonical hash
        payload = f"{timestamp}|{action}|{details}|{source_hash}|{prev_hash}|{actor}".encode("utf-8")
        this_hash = hashlib.sha256(payload).hexdigest()
        
        cursor = self._conn.cursor()
        cursor.execute("""
            INSERT INTO custody_events 
            (timestamp_utc, action, details, source_hash, prev_event_hash, this_event_hash, actor)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (timestamp, action, details, source_hash, prev_hash, this_hash, actor))
        
        self._conn.commit()

        if self._ledger_file:
            ledger_entry = {
                "timestamp_utc": timestamp,
                "action": action,
                "details": details,
                "source_hash": source_hash,
                "prev_event_hash": prev_hash,
                "this_event_hash": this_hash,
                "actor": actor
            }
            try:
                self._ledger_file.write(
                    json.dumps(ledger_entry, sort_keys=True, separators=(',', ':')) + "\n"
                )
                self._ledger_file.flush()
                os.fsync(self._ledger_file.fileno())
            except Exception as e:
                logger.error(f"JSONL write failed: {e}")

        self.last_hash = this_hash
        return this_hash

    def set_metadata(self, key: str, value: str):
        cursor = self._conn.cursor()
        cursor.execute("INSERT OR REPLACE INTO case_metadata (key, value) VALUES (?, ?)", (key, value))
        self._conn.commit()

    def get_metadata(self, key: str) -> Optional[str]:
        cursor = self._conn.cursor()
        cursor.execute("SELECT value FROM case_metadata WHERE key=?", (key,))
        row = cursor.fetchone()
        return row["value"] if row else None

    def add_baseline_file(self, path: str, size: int, mtime: int, sha256: str):
        cursor = self._conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO baseline_files (path, size, mtime, sha256) 
                VALUES (?, ?, ?, ?)
            """, (path, size, mtime, sha256))
            self._conn.commit()
        except sqlite3.IntegrityError:
            pass # Already exists

    def get_ledger_path(self) -> str:
        """Return the path to the JSONL append-only ledger."""
        return self._ledger_path

    def close(self):
        if self._ledger_file:
            try:
                self._ledger_file.close()
            except Exception:
                pass
        self._conn.close()
