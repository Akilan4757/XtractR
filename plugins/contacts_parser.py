"""
Contacts Parser Plugin — XtractR Forensic Platform
Extracts contacts from Android contacts2.db.
"""
import sqlite3
import os
import logging
from typing import List, Dict, Any
from core.plugin_interface import BasePlugin, Artifact
from core.vfs.base import BaseVFS

logger = logging.getLogger("xtractr.plugin.contacts")


class ContactsParser(BasePlugin):
    NAME = "Contacts Parser"
    VERSION = "1.1.0"
    DESCRIPTION = "Extracts Contacts from Android contacts2.db"

    def can_parse(self, vfs: BaseVFS) -> bool:
        return True

    def parse(self, vfs: BaseVFS, context: Dict[str, Any]) -> List[Artifact]:
        artifacts = []
        candidates = []
        for root, dirs, files in vfs.walk(""):
            for f in files:
                if f == "contacts2.db":
                    candidates.append(os.path.join(root, f))

        if not candidates:
            return []

        for db_path in candidates:
            try:
                with self.open_evidence_db(vfs, db_path) as conn:
                    cursor = conn.cursor()
                    parsed = False

                    # Strategy 1: view_data (modern Android)
                    try:
                        cursor.execute(
                            "SELECT display_name, data1, mimetype FROM view_data "
                            "WHERE mimetype='vnd.android.cursor.item/phone_v2'"
                        )
                        for row in cursor.fetchall():
                            try:
                                name = row["display_name"] or "Unknown"
                                number = row["data1"] or "Unknown"
                                artifacts.append(Artifact(
                                    artifact_id=f"contact_{self.derive_artifact_id('contact', name, number)}",
                                    artifact_type="CONTACT",
                                    source_path=db_path,
                                    timestamp_utc=0,
                                    parser_name=self.NAME,
                                    parser_version=self.VERSION,
                                    actor=str(number),
                                    details={"name": name, "number": number},
                                ))
                            except Exception as e:
                                self.errors.append(f"Contact row parse failed (Strategy 1): {e}")
                        parsed = True
                    except sqlite3.OperationalError as e:
                        logger.debug(f"view_data not available in {db_path}: {e}")

                    # Strategy 2: raw_contacts + data join (fallback)
                    if not parsed:
                        try:
                            cursor.execute("""
                                SELECT rc.display_name, d.data1
                                FROM raw_contacts rc
                                JOIN data d ON d.raw_contact_id = rc._id
                                JOIN mimetypes m ON m._id = d.mimetype_id
                                WHERE m.mimetype = 'vnd.android.cursor.item/phone_v2'
                            """)
                            for row in cursor.fetchall():
                                try:
                                    name = row["display_name"] or "Unknown"
                                    number = row["data1"] or "Unknown"
                                    artifacts.append(Artifact(
                                        artifact_id=f"contact_{self.derive_artifact_id('contact', name, number)}",
                                        artifact_type="CONTACT",
                                        source_path=db_path,
                                        timestamp_utc=0,
                                        parser_name=self.NAME,
                                        parser_version=self.VERSION,
                                        actor=str(number),
                                        details={"name": name, "number": number},
                                    ))
                                except Exception as e:
                                    self.errors.append(f"Contact row parse failed (Strategy 2): {e}")
                        except sqlite3.OperationalError as e:
                            logger.warning(f"Both strategies failed on {db_path}: {e}")
                            self.errors.append(f"Both strategies failed on {db_path}: {e}")

            except Exception as e:
                logger.warning(f"Failed to process {db_path}: {e}")
                self.errors.append(f"Failed to process {db_path}: {e}")

        return artifacts
