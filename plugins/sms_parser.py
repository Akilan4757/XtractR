"""
SMS/MMS Parser Plugin — XtractR Forensic Platform
Extracts SMS/MMS messages from Android mmssms.db.
"""
import logging
from typing import List, Dict, Any
import sqlite3
import os
from core.plugin_interface import BasePlugin, Artifact
from core.vfs.base import BaseVFS

logger = logging.getLogger("xtractr.plugin.sms")


class SMSParser(BasePlugin):
    NAME = "SMS Parser"
    VERSION = "1.1.0"
    DESCRIPTION = "Extracts SMS/MMS from Android mmssms.db"

    def can_parse(self, vfs: BaseVFS) -> bool:
        return True

    def parse(self, vfs: BaseVFS, context: Dict[str, Any]) -> List[Artifact]:
        artifacts = []

        # Find DBs
        candidates = []
        for root, dirs, files in vfs.walk(""):
            for f in files:
                if f == "mmssms.db":
                    candidates.append(os.path.join(root, f))

        if not candidates:
            return []

        for db_path in candidates:
            try:
                with self.open_evidence_db(vfs, db_path) as conn:
                    cursor = conn.cursor()

                    # SMS Table
                    try:
                        cursor.execute("SELECT address, date, body, type, read FROM sms")
                        for row in cursor.fetchall():
                            try:
                                ts = self.normalize_timestamp(row["date"])
                                body = row["body"] or ""
                                address = str(row["address"] or "UNKNOWN")
                                artifacts.append(Artifact(
                                    artifact_id=f"sms_{self.derive_artifact_id('sms', row['date'], body[:64])}",
                                    artifact_type="SMS",
                                    source_path=db_path,
                                    timestamp_utc=ts,
                                    parser_name=self.NAME,
                                    parser_version=self.VERSION,
                                    actor=address,
                                    details={
                                        "body": body,
                                        "direction": "SENT" if row["type"] == 2 else "RECEIVED",
                                        "read": bool(row["read"]),
                                    },
                                ))
                            except Exception as e:
                                self.errors.append(f"SMS row parse failed: {e}")
                    except sqlite3.OperationalError as e:
                        logger.warning(f"Table query failed on {db_path}: {e}")
                        self.errors.append(f"Table query failed on {db_path}: {e}")

                    # MMS Table
                    try:
                        cursor.execute("""
                            SELECT _id, date, msg_box, sub, ct_l
                            FROM pdu WHERE msg_box IN (1, 2)
                        """)
                        for row in cursor.fetchall():
                            try:
                                ts = self.normalize_timestamp(row["date"])
                                subject = row["sub"] or ""
                                content_location = row["ct_l"] or ""
                                direction = "RECEIVED" if row["msg_box"] == 1 else "SENT"
                                artifacts.append(Artifact(
                                    artifact_id=f"mms_{row['_id']}_{ts}",
                                    artifact_type="MMS",
                                    source_path=db_path,
                                    timestamp_utc=ts,
                                    parser_name=self.NAME,
                                    parser_version=self.VERSION,
                                    actor="DEVICE",
                                    details={
                                        "subject": subject,
                                        "content_location": content_location,
                                        "direction": direction,
                                    },
                                ))
                            except Exception as e:
                                self.errors.append(f"MMS row parse failed: {e}")
                    except sqlite3.OperationalError as e:
                        logger.debug(f"MMS table not found in {db_path}: {e}")

            except Exception as e:
                logger.warning(f"Failed to process {db_path}: {e}")
                self.errors.append(f"Failed to process {db_path}: {e}")

        return artifacts
