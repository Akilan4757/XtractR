import pytest
import sqlite3
import os
from orchestrator.database import init_db
from orchestrator.ledger import CustodyLedger
from orchestrator.hashing import calculate_event_hash

@pytest.fixture
def temp_case(tmp_path):
    case_dir = tmp_path / "test_case"
    init_db(str(case_dir))
    return str(case_dir)

def test_ledger_chaining(temp_case):
    ledger = CustodyLedger(temp_case)
    
    # Event 1
    h1 = ledger.log_event("INV-001", "INIT")
    
    # Event 2
    h2 = ledger.log_event("INV-001", "SCAN")
    
    ledger.close()
    
    # Verify manually
    conn = sqlite3.connect(os.path.join(temp_case, "case.db"))
    cursor = conn.cursor()
    cursor.execute("SELECT event_hash, prev_event_hash FROM custody_events ORDER BY event_id")
    rows = cursor.fetchall()
    conn.close()
    
    # Check Row 1
    assert rows[0][0] == h1
    assert rows[0][1] == "GENESIS_HASH"
    
    # Check Row 2
    assert rows[1][0] == h2
    assert rows[1][1] == h1

def test_tamper_detection(temp_case):
    ledger = CustodyLedger(temp_case)
    h1 = ledger.log_event("INV-001", "INIT")
    h2 = ledger.log_event("INV-001", "SCAN")
    ledger.close()
    
    # Modify Row 1 Hash
    db_path = os.path.join(temp_case, "case.db")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("UPDATE custody_events SET event_hash = 'tampered' WHERE event_id = 1")
    conn.commit()
    conn.close()
    
    # Verify using our independent logic (simulated)
    # Re-using logic from xtractr_verify.py
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM custody_events ORDER BY event_id ASC")
    rows = cursor.fetchall()
    
    violation = False
    prev_hash = "GENESIS_HASH"
    for row in rows:
        claimed_prev = row[6]
        claimed_hash = row[7]
        
        if claimed_prev != prev_hash:
            violation = True
            break
            
        # Recalc
        ts, inv, act, tgt, fh, notes = row[1], row[2], row[3], row[4], row[5], row[8]
        payload = f"{ts}|{inv}|{act}|{tgt or ''}|{fh or ''}|{notes or ''}"
        
        # This will fail for row 1 because we changed the claimed_hash, but not the payload
        # Wait, if we change the displayed hash, the verification fails because (payload + prev) != claimed
        from orchestrator.hashing import calculate_string_hash
        calc = calculate_string_hash(payload + prev_hash)
        if calc != claimed_hash:
            violation = True
            break
        prev_hash = claimed_hash
        
    assert violation == True
