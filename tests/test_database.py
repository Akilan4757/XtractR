import pytest
import sqlite3
import os
import time
from core.database import CaseDatabase
from core.integrity import verify_ledger_integrity
from core.baseline import create_baseline, check_drift
from core.vfs.directory import DirectoryVFS

@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "case.db")

@pytest.fixture
def sample_vfs(tmp_path):
    d = tmp_path / "evidence"
    d.mkdir()
    (d / "file1.txt").write_text("content1")
    return DirectoryVFS(str(d)), str(d)

def test_schema_init(db_path):
    db = CaseDatabase(db_path)
    # Check tables
    cursor = db._conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row[0] for row in cursor.fetchall()]
    assert "case_metadata" in tables
    assert "custody_events" in tables
    assert "baseline_files" in tables
    db.close()

def test_merkle_ledger(db_path):
    db = CaseDatabase(db_path)
    
    # Genesis
    genesis = db.last_hash
    assert genesis == "GENESIS_HASH_00000000000000000000000000000000"
    
    # Event 1
    h1 = db.log_event("INIT", "Case Initialized")
    assert h1 != genesis # Should update from genesis
    assert db.last_hash == h1

    # Event 2
    h2 = db.log_event("SCAN", "Scan Started")
    assert h2 != h1
    
    # Verify Chain
    assert verify_ledger_integrity(db_path)
    db.close()

def test_tamper_detection(db_path):
    db = CaseDatabase(db_path)
    db.log_event("A", "A")
    db.log_event("B", "B")
    db.close()
    
    # Tamper with DB
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    # Change first event action but keep hash same -> Mismatch!
    cursor.execute("UPDATE custody_events SET action='TAMPERED' WHERE id=1")
    conn.commit()
    conn.close()
    
    assert verify_ledger_integrity(db_path) == False

def test_baseline_and_drift(db_path, sample_vfs):
    vfs, real_path = sample_vfs
    db = CaseDatabase(db_path)
    
    # 1. Create Baseline
    count, bytes_total = create_baseline(vfs, db)
    assert count == 1
    
    # 2. Check No Drift
    drift = check_drift(vfs, db)
    assert not drift["modified"]
    assert not drift["missing"]
    assert not drift["new"]
    
    # 3. Induce Drift (Modify File)
    with open(os.path.join(real_path, "file1.txt"), "w") as f:
        f.write("modified_content")
    
    drift = check_drift(vfs, db)
    assert len(drift["modified"]) == 1
    assert "file1.txt" in drift["modified"][0]
    
    # 4. Induce New File
    with open(os.path.join(real_path, "new.txt"), "w") as f:
        f.write("new")
        
    drift = check_drift(vfs, db)
    assert "new.txt" in drift["new"]
    
    db.close()
