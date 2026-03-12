"""
WhatsApp Message Parser Plugin — XtractR Forensic Platform
Extracts chat messages from Android WhatsApp msgstore.db / wa.db.
Supports both legacy and current schema versions.
"""
import sqlite3
import tempfile
import os
import logging
from typing import List, Dict, Any
from core.plugin_interface import BasePlugin, Artifact
from core.vfs.base import BaseVFS

logger = logging.getLogger("xtractr.plugin.whatsapp")

# WhatsApp database filenames across versions
WA_DB_NAMES = {"msgstore.db", "wa.db"}


class WhatsAppParser(BasePlugin):
    NAME = "WhatsApp Parser"
    VERSION = "1.0.0"
    DESCRIPTION = "Extracts WhatsApp messages, group info, and media stubs from msgstore.db"

    def can_parse(self, vfs: BaseVFS) -> bool:
        return True

    def parse(self, vfs: BaseVFS, context: Dict[str, Any]) -> List[Artifact]:
        artifacts = []

        # Discover all WhatsApp DBs
        msg_dbs = []
        for root, dirs, files in vfs.walk(""):
            for f in files:
                if f in WA_DB_NAMES:
                    msg_dbs.append(os.path.join(root, f))

        for db_path in msg_dbs:
            try:
                with tempfile.NamedTemporaryFile(suffix=".db", delete=True) as tmp:
                    tmp.write(vfs.read_bytes(db_path))
                    tmp.flush()

                    conn = sqlite3.connect(tmp.name)
                    conn.row_factory = sqlite3.Row
                    cursor = conn.cursor()

                    # Detect schema version — newer WA uses 'message' table
                    tables = {row[0] for row in cursor.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    ).fetchall()}

                    if "message" in tables:
                        self._parse_modern_schema(cursor, db_path, artifacts)
                    elif "messages" in tables:
                        self._parse_legacy_schema(cursor, db_path, artifacts)
                    else:
                        logger.warning(f"[WhatsApp] No known message table in {db_path}")

                    conn.close()
            except Exception as e:
                logger.warning(f"[WhatsApp] Failed to process {db_path}: {e}")

        return artifacts

    def _parse_modern_schema(self, cursor, db_path: str, artifacts: List[Artifact]):
        """WhatsApp 2023+ schema: 'message' table with chat_row_id FK."""
        try:
            cursor.execute("""
                SELECT m._id, m.chat_row_id, m.from_me, m.timestamp,
                       m.text_data, m.message_type,
                       c.raw_string_jid AS chat_jid
                FROM message m
                LEFT JOIN chat c ON c._id = m.chat_row_id
                ORDER BY m.timestamp ASC
            """)
            for row in cursor.fetchall():
                ts = self.normalize_timestamp(row["timestamp"])
                body = row["text_data"] or ""
                media_type = self._media_type_label(row["message_type"])
                direction = "SENT" if row["from_me"] == 1 else "RECEIVED"
                chat_jid = row["chat_jid"] or "unknown"

                artifacts.append(Artifact(
                    artifact_id=f"wa_msg_{row['_id']}",
                    artifact_type="WHATSAPP_MSG",
                    source_path=db_path,
                    timestamp_utc=ts,
                    parser_name=self.NAME,
                    parser_version=self.VERSION,
                    actor=chat_jid,
                    details={
                        "body": body[:4096],
                        "direction": direction,
                        "chat_id": str(row["chat_row_id"]),
                        "media_type": media_type,
                    },
                ))
        except sqlite3.OperationalError as e:
            logger.warning(f"[WhatsApp] Modern schema query failed: {e}")

    def _parse_legacy_schema(self, cursor, db_path: str, artifacts: List[Artifact]):
        """Legacy schema: 'messages' table with key_remote_jid."""
        try:
            cursor.execute("""
                SELECT _id, key_remote_jid, key_from_me, timestamp,
                       data, media_wa_type
                FROM messages
                ORDER BY timestamp ASC
            """)
            for row in cursor.fetchall():
                ts = self.normalize_timestamp(row["timestamp"])
                body = row["data"] or ""
                media_type = self._media_type_label(row["media_wa_type"])
                direction = "SENT" if row["key_from_me"] == 1 else "RECEIVED"
                jid = row["key_remote_jid"] or "unknown"

                artifacts.append(Artifact(
                    artifact_id=f"wa_msg_{row['_id']}",
                    artifact_type="WHATSAPP_MSG",
                    source_path=db_path,
                    timestamp_utc=ts,
                    parser_name=self.NAME,
                    parser_version=self.VERSION,
                    actor=jid,
                    details={
                        "body": body[:4096],
                        "direction": direction,
                        "chat_id": jid,
                        "media_type": media_type,
                    },
                ))
        except sqlite3.OperationalError as e:
            logger.warning(f"[WhatsApp] Legacy schema query failed: {e}")

    @staticmethod
    def _media_type_label(mt) -> str:
        _MAP = {
            0: "TEXT", 1: "IMAGE", 2: "AUDIO", 3: "VIDEO",
            4: "CONTACT_CARD", 5: "LOCATION", 8: "DOCUMENT",
            9: "MISSED_CALL", 10: "CALL_LOG", 13: "GIF",
            15: "STICKER", 16: "LIVE_LOCATION",
        }
        try:
            return _MAP.get(int(mt), f"TYPE_{mt}")
        except (TypeError, ValueError):
            return "UNKNOWN"
