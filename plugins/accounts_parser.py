import sqlite3
import tempfile
import os
from typing import List, Dict, Any
from core.plugin_interface import BasePlugin, Artifact
from core.vfs.base import BaseVFS

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
                with tempfile.NamedTemporaryFile() as tmp:
                    tmp.write(vfs.read_bytes(db_path))
                    tmp.flush()
                    
                    conn = sqlite3.connect(tmp.name)
                    conn.row_factory = sqlite3.Row
                    cursor = conn.cursor()
                    try:
                        cursor.execute("SELECT name, type FROM accounts")
                        for row in cursor.fetchall():
                            artifacts.append(Artifact(
                                artifact_id=f"acc_{hash(row['name'])}",
                                artifact_type="ACCOUNT",
                                source_path=db_path,
                                timestamp_utc=0,
                                parser_name=self.NAME,
                                parser_version=self.VERSION,
                                actor="DEVICE",
                                details={"name": row["name"], "type": row["type"]}
                            ))
                    except:
                        pass
                    conn.close()
            except:
                pass
        return artifacts
