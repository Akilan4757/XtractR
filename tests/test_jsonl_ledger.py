"""
JSONL Append-Only Ledger Test Suite

Verifies:
  1. Every log_event writes to BOTH SQLite and JSONL
  2. JSONL entries match SQLite entries
  3. Discrepancies between JSONL and SQLite are detectable
"""
import os
import sys
import json
import shutil
import tempfile
import sqlite3
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.database import CaseDatabase


@pytest.fixture
def case_db():
    tmpdir = tempfile.mkdtemp(prefix="jsonl_test_")
    db_path = os.path.join(tmpdir, "case.db")
    db = CaseDatabase(db_path)
    db.set_metadata("case_id", "JSONL-TEST-001")
    yield db, tmpdir
    db.close()
    shutil.rmtree(tmpdir, ignore_errors=True)


class TestJSONLLedger:
    def test_jsonl_file_created(self, case_db):
        """JSONL file should be created alongside the database."""
        db, tmpdir = case_db
        ledger_path = db.get_ledger_path()
        assert os.path.exists(ledger_path), "JSONL ledger file should exist"

    def test_events_written_to_both(self, case_db):
        """Each log_event should appear in both SQLite and JSONL."""
        db, tmpdir = case_db

        db.log_event("TEST_ACTION_1", "First test event", actor="TESTER")
        db.log_event("TEST_ACTION_2", "Second test event", actor="TESTER")
        db.log_event("TEST_ACTION_3", "Third test event", actor="TESTER")

        # Check SQLite
        cursor = db._conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM custody_events")
        sqlite_count = cursor.fetchone()[0]
        assert sqlite_count == 3

        # Check JSONL
        ledger_path = db.get_ledger_path()
        with open(ledger_path, "r") as f:
            lines = [line.strip() for line in f if line.strip()]
        assert len(lines) == 3

        # Compare hashes
        cursor.execute("SELECT this_event_hash FROM custody_events ORDER BY id ASC")
        sqlite_hashes = [row[0] for row in cursor.fetchall()]

        jsonl_hashes = []
        for line in lines:
            entry = json.loads(line)
            jsonl_hashes.append(entry["this_event_hash"])

        assert sqlite_hashes == jsonl_hashes, "Hashes must match between SQLite and JSONL"

    def test_jsonl_chaining_integrity(self, case_db):
        """JSONL entries should form a valid hash chain."""
        db, tmpdir = case_db

        db.log_event("CHAIN_1", "First", actor="SYSTEM")
        db.log_event("CHAIN_2", "Second", actor="SYSTEM")
        db.log_event("CHAIN_3", "Third", actor="SYSTEM")

        ledger_path = db.get_ledger_path()
        with open(ledger_path, "r") as f:
            entries = [json.loads(line) for line in f if line.strip()]

        # First entry should reference GENESIS hash
        assert entries[0]["prev_event_hash"].startswith("GENESIS_HASH")

        # Each subsequent entry's prev should match the previous entry's this
        for i in range(1, len(entries)):
            assert entries[i]["prev_event_hash"] == entries[i - 1]["this_event_hash"], (
                f"Chain broken at index {i}"
            )

    def test_sqlite_tampering_detectable(self, case_db):
        """Modifying SQLite but not JSONL should create a mismatch."""
        db, tmpdir = case_db

        db.log_event("NORMAL_EVENT", "Clean event", actor="SYSTEM")
        db.log_event("TAMPER_TARGET", "This will be tampered in SQLite", actor="SYSTEM")

        # Get the JSONL hash for the second event
        ledger_path = db.get_ledger_path()
        with open(ledger_path, "r") as f:
            entries = [json.loads(line) for line in f if line.strip()]

        jsonl_hash = entries[1]["this_event_hash"]

        # Tamper SQLite directly
        cursor = db._conn.cursor()
        cursor.execute("UPDATE custody_events SET details = 'TAMPERED!' WHERE id = 2")
        db._conn.commit()

        # Re-read from SQLite
        cursor.execute("SELECT this_event_hash FROM custody_events WHERE id = 2")
        sqlite_hash = cursor.fetchone()[0]

        # The hash in SQLite column hasn't changed (the attacker would need
        # to recalculate it), but the stored details no longer match the hash.
        # Cross-validation by recalculating should catch this.
        assert sqlite_hash == jsonl_hash, (
            "SQLite still has the original hash (attacker didn't recalc)"
        )

        # But if we verify the hash against actual content, it will fail
        import hashlib
        cursor.execute("SELECT timestamp_utc, action, details, source_hash, prev_event_hash, actor FROM custody_events WHERE id = 2")
        row = cursor.fetchone()
        payload = f"{row[0]}|{row[1]}|{row[2]}|{row[3]}|{row[4]}|{row[5]}".encode("utf-8")
        recalc_hash = hashlib.sha256(payload).hexdigest()

        assert recalc_hash != sqlite_hash, (
            "Recalculated hash should NOT match stored hash after tampering"
        )

    def test_ledger_path_accessible(self, case_db):
        """get_ledger_path() should return the correct path."""
        db, tmpdir = case_db
        path = db.get_ledger_path()
        assert path.endswith("_custody_ledger.jsonl")
        assert os.path.dirname(path) == tmpdir
