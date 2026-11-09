"""
Instagram DM Parser Plugin — XtractR Forensic Platform
Extracts direct messages and user metadata from Android Instagram databases.
"""
import sqlite3
import os
import json
import logging
from typing import List, Dict, Any
from core.plugin_interface import BasePlugin, Artifact
from core.vfs.base import BaseVFS

logger = logging.getLogger("xtractr.plugin.instagram")

IG_DB_NAMES = {"direct.db", "direct_messages.db"}


class InstagramParser(BasePlugin):
    NAME = "Instagram Parser"
    VERSION = "1.0.0"
    DESCRIPTION = "Extracts Instagram DMs and user metadata"

    def can_parse(self, vfs: BaseVFS) -> bool:
        return True

    def parse(self, vfs: BaseVFS, context: Dict[str, Any]) -> List[Artifact]:
        artifacts = []

        candidates = []
        for root, dirs, files in vfs.walk(""):
            for f in files:
                if f in IG_DB_NAMES:
                    candidates.append(os.path.join(root, f))

        for db_path in candidates:
            try:
                with self.open_evidence_db(vfs, db_path) as conn:
                    cursor = conn.cursor()

                    tables = {row[0] for row in cursor.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    ).fetchall()}

                    # messages table
                    if "messages" in tables:
                        try:
                            cursor.execute("""
                                SELECT _id, thread_key, user_id, timestamp,
                                       message, message_type
                                FROM messages ORDER BY timestamp ASC
                            """)
                            for row in cursor.fetchall():
                                try:
                                    ts = self.normalize_timestamp(row["timestamp"])
                                    body = row["message"] or ""
                                    msg_type = row["message_type"] or "TEXT"

                                    artifacts.append(Artifact(
                                        artifact_id=f"ig_msg_{row['_id']}",
                                        artifact_type="INSTAGRAM_MSG",
                                        source_path=db_path,
                                        timestamp_utc=ts,
                                        parser_name=self.NAME,
                                        parser_version=self.VERSION,
                                        actor=str(row["user_id"] or "unknown"),
                                        details={
                                            "body": body[:4096],
                                            "thread_key": str(row["thread_key"] or ""),
                                            "message_type": str(msg_type),
                                        },
                                    ))
                                except Exception as e:
                                    self.errors.append(f"IG message row parse failed: {e}")
                        except sqlite3.OperationalError as e:
                            logger.warning(f"messages query failed on {db_path}: {e}")
                            self.errors.append(f"messages query failed on {db_path}: {e}")

                    # threads table
                    if "threads" in tables:
                        try:
                            cursor.execute("""
                                SELECT thread_key, thread_type, admin_user_id, thread_title
                                FROM threads
                            """)
                            for row in cursor.fetchall():
                                try:
                                    title = row["thread_title"] or ""
                                    t_key = str(row["thread_key"])
                                    artifacts.append(Artifact(
                                        artifact_id=f"ig_thread_{self.derive_artifact_id('ig_t', t_key)}",
                                        artifact_type="INSTAGRAM_THREAD",
                                        source_path=db_path,
                                        timestamp_utc=0,
                                        parser_name=self.NAME,
                                        parser_version=self.VERSION,
                                        actor=str(row["admin_user_id"] or "unknown"),
                                        details={
                                            "thread_key": t_key,
                                            "thread_type": str(row["thread_type"]),
                                            "title": title,
                                        },
                                    ))
                                except Exception as e:
                                    self.errors.append(f"IG thread row parse failed: {e}")
                        except sqlite3.OperationalError as e:
                            logger.debug(f"threads query failed: {e}")

            except Exception as e:
                logger.warning(f"Failed to process {db_path}: {e}")
                self.errors.append(f"Failed to process {db_path}: {e}")

        return artifacts
