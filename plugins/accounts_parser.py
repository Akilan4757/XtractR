import os
import sqlite3
import logging
from typing import List, Dict, Any
from core.plugin_interface import BasePlugin, Artifact
from core.vfs.base import BaseVFS

logger = logging.getLogger("xtractr.plugin.accounts")

class AccountsParser(BasePlugin):
    NAME = "Accounts Parser"
    VERSION = "1.0.0"
    DESCRIPTION = "Extracts Account info from accounts.db"

    def can_parse(self, vfs: BaseVFS) -> bool:
        return True

    def parse(self, vfs: BaseVFS, context: Dict[str, Any]) -> List[Artifact]:
        artifacts = []
        candidates = []
        for root, dirs, files in vfs.walk(""):
             if "accounts.db" in files:
                candidates.append(os.path.join(root, "accounts.db"))
        
        for db_path in candidates:
            try:
                with self.open_evidence_db(vfs, db_path) as conn:
                    cursor = conn.cursor()
                    try:
                        cursor.execute("SELECT name, type FROM accounts")
                        for row in cursor.fetchall():
                            try:
                                artifacts.append(Artifact(
                                    artifact_id=self.derive_artifact_id("acc", row['name']),
                                    artifact_type="ACCOUNT",
                                    source_path=db_path,
                                    timestamp_utc=0,
                                    parser_name=self.NAME,
                                    parser_version=self.VERSION,
                                    actor="DEVICE",
                                    details={"name": row["name"], "type": row["type"]}
                                ))
                            except Exception as e:
                                self.errors.append(f"Account row parse failed: {e}")
                    except sqlite3.OperationalError as e:
                        logger.warning(f"accounts table query failed: {e}")
                        self.errors.append(f"accounts table query failed: {e}")
            except Exception as e:
                logger.warning(f"Failed to process {db_path}: {e}")
                self.errors.append(f"Failed to process {db_path}: {e}")
        return artifacts
