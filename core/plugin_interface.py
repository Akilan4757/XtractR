import abc
import json
import time
import contextlib
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from core.vfs.base import BaseVFS

@dataclass
class Artifact:
    """
    Standardized Forensic Artifact.
    ALL plugins must return a list of these objects.
    """
    artifact_id: str  # Unique ID for this artifact instance
    artifact_type: str # e.g., "SMS", "CALL_LOG", "CHROME_HISTORY"
    source_path: str # Path in VFS
    timestamp_utc: int # Unix ms
    parser_name: str
    parser_version: str
    actor: str # Phone number, email, or "DEVICE"
    details: Dict[str, Any] # The actual content
    reference_hash: Optional[str] = None # Hash of source file
    confidence: float = 1.0 # 0.0 - 1.0
    
    def to_dict(self):
        return asdict(self)

class BasePlugin(abc.ABC):
    """
    Abstract Base Class for XtractR Plugins.
    """
    NAME = "BasePlugin"
    VERSION = "0.0.0"
    DESCRIPTION = "Abstract Base"
    AUTHOR = "XtractR Core"
    DEPENDENCIES = []

    def __init__(self):
        self.errors: List[str] = []

    @abc.abstractmethod
    def can_parse(self, vfs: BaseVFS) -> bool:
        """
        Quick check if this plugin is applicable to the evidence.
        Should be fast (file existence checks).
        """
        pass

    @abc.abstractmethod
    def parse(self, vfs: BaseVFS, context: Dict[str, Any]) -> List[Artifact]:
        """
        Extract artifacts from the evidence.
        Must operate within sandbox limits (time/memory).
        """
        pass
    
    def normalize_timestamp(self, ts) -> int:
        """Helper to convert various timestamp formats to UTC ms epoch."""
        # Generic implementation, plugins can override or use utils
        if not ts: return 0
        try:
            return int(ts)
        except:
            return 0

    def derive_artifact_id(self, prefix: str, *args) -> str:
        """
        Derives a stable, deterministic, cryptographic identifier for an artifact.
        """
        import hashlib
        h = hashlib.sha256()
        for arg in args:
            h.update(str(arg).encode('utf-8'))
        return f"{prefix}_{h.hexdigest()[:16]}"

    def get_reference_hash(self, vfs: BaseVFS, path: str) -> str:
        """
        Get or compute SHA-256 hash of a VFS file.
        """
        if not hasattr(self, "_evidence_hashes"):
            self._evidence_hashes = {}
        if path in self._evidence_hashes:
            return self._evidence_hashes[path]
        try:
            import hashlib
            data = vfs.read_bytes(path)
            h = hashlib.sha256(data).hexdigest()
            self._evidence_hashes[path] = h
            return h
        except Exception:
            return "UNKNOWN"

    @contextlib.contextmanager
    def open_evidence_db(self, vfs: BaseVFS, db_path: str, required_tables: List[str] = []):
        """
        Safely extracts an SQLite database from the VFS to a temp file,
        opens it in READ-ONLY mode, verifies required tables (schema validation),
        and yields the sqlite3.Connection.
        """
        import sqlite3
        import tempfile
        import os
        
        temp_file = None
        conn = None
        try:
            # Materialize to temp file
            suffix = os.path.splitext(os.path.basename(db_path))[1] or ".db"
            temp_file = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
            data = vfs.read_bytes(db_path)
            
            # Cache the database file hash
            if not hasattr(self, "_evidence_hashes"):
                self._evidence_hashes = {}
            import hashlib
            self._evidence_hashes[db_path] = hashlib.sha256(data).hexdigest()

            temp_file.write(data)
            temp_file.close() # Close to allow SQLite to open it on Windows

            # Open read-only URI
            db_uri = f"file:{os.path.abspath(temp_file.name)}?mode=ro"
            conn = sqlite3.connect(db_uri, uri=True)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Schema validation
            if required_tables:
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                existing_tables = {row["name"] for row in cursor.fetchall()}
                for table in required_tables:
                    if table not in existing_tables:
                        raise sqlite3.OperationalError(f"Required table '{table}' not found in database schema")
            
            yield conn
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass
            if temp_file:
                try:
                    os.unlink(temp_file.name)
                except Exception:
                    pass
