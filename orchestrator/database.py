import sqlite3
import os
import logging

logger = logging.getLogger("xtractr.database")

SCHEMA = """
CREATE TABLE IF NOT EXISTS custody_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_utc TEXT NOT NULL,
    investigator_id TEXT NOT NULL,
    action_type TEXT NOT NULL,
    target_path TEXT,
    file_hash_sha256 TEXT,
    prev_event_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL,
    notes TEXT,
    tool_version TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS baseline_files (
    relative_path TEXT PRIMARY KEY,
    sha256 TEXT NOT NULL,
    size INTEGER NOT NULL,
    mtime_utc TEXT NOT NULL,
    inode INTEGER
);

CREATE TABLE IF NOT EXISTS case_seal (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    merkle_root TEXT NOT NULL,
    created_at_utc TEXT NOT NULL,
    algorithm_version TEXT NOT NULL DEFAULT 'SHA256-Tree-v1'
);

CREATE TABLE IF NOT EXISTS investigator_profile (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    investigator_id TEXT NOT NULL,
    organization TEXT NOT NULL,
    designation TEXT NOT NULL,
    contact TEXT,
    location TEXT,
    machine_id TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ledger_seal (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_hash_sha256 TEXT NOT NULL,
    signature_hex TEXT NOT NULL,
    event_count INTEGER NOT NULL,
    created_at_utc TEXT NOT NULL,
    algorithm_version TEXT NOT NULL DEFAULT 'Ed25519-SHA256-v1'
);

CREATE TABLE IF NOT EXISTS artifact_signatures (
    relative_path TEXT PRIMARY KEY,
    file_hash_sha256 TEXT NOT NULL,
    signature_hex TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
);
"""

def init_db(case_dir):
    """Initialize the case database with schema."""
    db_path = os.path.join(case_dir, "case.db")
    os.makedirs(case_dir, exist_ok=True)
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.executescript(SCHEMA)
    conn.commit()
    conn.close()
    return db_path

def get_connection(case_dir):
    """Get a connection to the case database."""
    db_path = os.path.join(case_dir, "case.db")
    if not os.path.exists(db_path):
        raise FileNotFoundError(f"Case database not found at {db_path}. Run 'init' first.")
    return sqlite3.connect(db_path)
