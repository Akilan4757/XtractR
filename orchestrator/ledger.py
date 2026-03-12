import sqlite3
import datetime
import logging
from .database import get_connection
from .hashing import calculate_string_hash

logger = logging.getLogger("xtractr.ledger")

class CustodyLedger:
    def __init__(self, case_dir, connection=None):
        self.case_dir = case_dir
        self.conn = connection if connection else get_connection(case_dir)
        self.shared = connection is not None

    def close(self):
        if not self.shared:
            self.conn.close()

    def _get_last_event_hash(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT event_hash FROM custody_events ORDER BY event_id DESC LIMIT 1")
        row = cursor.fetchone()
        return row[0] if row else "GENESIS_HASH"

    def log_event(self, investigator_id, action_type, target_path=None, file_hash=None, notes=None):
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        prev_hash = self._get_last_event_hash()
        
        # Payload for hashing (canonical representation)
        payload = f"{timestamp}|{investigator_id}|{action_type}|{target_path or ''}|{file_hash or ''}|{notes or ''}"
        
        # Calculate chained hash: SHA256(payload + prev_hash)
        event_hash = calculate_string_hash(payload + prev_hash)
        
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO custody_events (
                timestamp_utc, investigator_id, action_type, target_path, 
                file_hash_sha256, prev_event_hash, event_hash, notes, tool_version
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            timestamp, investigator_id, action_type, target_path, 
            file_hash, prev_hash, event_hash, notes, "v2.0.0-MVP"
        ))
        self.conn.commit()
        logger.info(f"Custody Event Logged: {action_type} - {event_hash[:8]}")
        return event_hash

    def seal_ledger(self, private_key):
        """
        Compute SHA256 snapshot of all events and sign it.
        Returns: (snapshot_hash, signature_hex)
        """
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM custody_events ORDER BY event_id ASC")
        events = cursor.fetchall()
        
        # Canonical Serialization for Snapshot
        # Format: event_hash1|event_hash2|...|event_hashN
        snapshot_payload = "|".join([row[7] for row in events])
        snapshot_hash = calculate_string_hash(snapshot_payload)
        
        # Sign it
        from .signing import sign_data
        signature = sign_data(private_key, snapshot_hash.encode("utf-8"))
        signature_hex = signature.hex()
        
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        
        cursor.execute("""
            INSERT INTO ledger_seal (
                snapshot_hash_sha256, signature_hex, event_count, created_at_utc
            ) VALUES (?, ?, ?, ?)
        """, (snapshot_hash, signature_hex, len(events), timestamp))
        self.conn.commit()
        
        logger.info(f"Ledger Sealed. Snapshot: {snapshot_hash[:16]}...")
        return snapshot_hash, signature_hex
