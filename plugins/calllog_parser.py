"""
Call Log Parser Plugin — XtractR Forensic Platform
Extracts call logs from Android contacts2.db / calllog.db.
"""
import sqlite3
import tempfile
import os
import logging
from typing import List, Dict, Any
from core.plugin_interface import BasePlugin, Artifact
from core.vfs.base import BaseVFS

logger = logging.getLogger("xtractr.plugin.calllog")

CALL_TYPE_MAP = {
    1: "INCOMING",
    2: "OUTGOING",
    3: "MISSED",
    4: "VOICEMAIL",
    5: "REJECTED",
    6: "BLOCKED",
    7: "ANSWERED_EXTERNALLY",
}


class CallLogParser(BasePlugin):
    NAME = "Call Log Parser"
    VERSION = "1.1.0"
    DESCRIPTION = "Extracts Call Logs from Android contacts2.db/calllog.db"

    def can_parse(self, vfs: BaseVFS) -> bool:
        return True

    def parse(self, vfs: BaseVFS, context: Dict[str, Any]) -> List[Artifact]:
        artifacts = []
        candidates = []
        for root, dirs, files in vfs.walk(""):
            for f in files:
                if f in ("contacts2.db", "calllog.db"):
                    candidates.append(os.path.join(root, f))

        if not candidates:
            return []

        for db_path in candidates:
            try:
                with tempfile.NamedTemporaryFile(suffix=".db", delete=True) as tmp:
                    tmp.write(vfs.read_bytes(db_path))
                    tmp.flush()

                    conn = sqlite3.connect(tmp.name)
                    conn.row_factory = sqlite3.Row
                    cursor = conn.cursor()

                    try:
                        cursor.execute("SELECT number, date, duration, type FROM calls")
                        for row in cursor.fetchall():
                            c_type = CALL_TYPE_MAP.get(row["type"], "UNKNOWN")
                            number = str(row["number"] or "UNKNOWN")

                            artifacts.append(Artifact(
                                artifact_id=f"call_{row['date']}_{abs(hash(number))}",
                                artifact_type="CALL_LOG",
                                source_path=db_path,
                                timestamp_utc=self.normalize_timestamp(row["date"]),
                                parser_name=self.NAME,
                                parser_version=self.VERSION,
                                actor=number,
                                details={
                                    "duration_sec": row["duration"],
                                    "type": c_type,
                                },
                            ))
                    except sqlite3.OperationalError as e:
                        logger.warning(f"[CallLogParser] Table query failed on {db_path}: {e}")

                    conn.close()
            except Exception as e:
                logger.warning(f"[CallLogParser] Failed to process {db_path}: {e}")

        return artifacts
