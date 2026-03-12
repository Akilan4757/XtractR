import hashlib
import json
import logging
from typing import List, BinaryIO, Any

logger = logging.getLogger("xtractr.integrity")

def canonical_json(obj: Any) -> bytes:
    """
    Canonical JSON serialization (INV-003).
    Produces identical byte output for identical logical content.
    All hashed JSON MUST pass through this function.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(',', ':'),
        ensure_ascii=True,
        default=str
    ).encode('utf-8')

def hash_file(file_obj: BinaryIO, chunk_size: int = 65536) -> str:
    """
    Compute SHA256 of a file-like object.
    """
    h = hashlib.sha256()
    while True:
        chunk = file_obj.read(chunk_size)
        if not chunk: break
        h.update(chunk)
    return h.hexdigest()

def compute_merkle_root(hashes: List[str]) -> str:
    """
    Compute Merkle Root for a list of hex hashes.
    Sorts input for determinism.
    """
    if not hashes:
        return hashlib.sha256(b"EMPTY").hexdigest()

    leaves = sorted(hashes)
    current_level = leaves

    while len(current_level) > 1:
        next_level = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            # Duplicate last if odd
            right = current_level[i + 1] if i + 1 < len(current_level) else left
            combined = hashlib.sha256((left + right).encode('utf-8')).hexdigest()
            next_level.append(combined)
        current_level = next_level

    return current_level[0]


def hash_artifact(artifact_dict: dict) -> str:
    """
    Compute SHA-256 of a single artifact's canonical JSON form.
    Input must be a dict (not an Artifact object).
    """
    return hashlib.sha256(canonical_json(artifact_dict)).hexdigest()


def compute_system_root(artifact_root: str, log_root: str) -> str:
    """
    Combine artifact Merkle root and log Merkle root into
    a single system root.  system_root = SHA256(artifact_root || log_root)
    """
    return hashlib.sha256(
        (artifact_root + log_root).encode('utf-8')
    ).hexdigest()

def verify_ledger_integrity(db_path: str) -> bool:
    """
    Verify the entire hash chain of the custody ledger.
    """
    import sqlite3
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM custody_events ORDER BY id ASC")
    rows = cursor.fetchall()
    conn.close()
    
    expected_prev = "GENESIS_HASH_00000000000000000000000000000000"
    
    for row in rows:
        # 1. Check Link
        if row["prev_event_hash"] != expected_prev:
            logger.error(f"Ledger Break at ID {row['id']}: Link Mismatch")
            return False
        
        # 2. Recompute Hash
        payload = f"{row['timestamp_utc']}|{row['action']}|{row['details']}|{row['source_hash']}|{row['prev_event_hash']}|{row['actor']}".encode("utf-8")
        recalc = hashlib.sha256(payload).hexdigest()
        
        if recalc != row["this_event_hash"]:
            logger.error(f"Ledger Tamper at ID {row['id']}: Hash Mismatch")
            return False
            
        expected_prev = row["this_event_hash"]
        
    return True
