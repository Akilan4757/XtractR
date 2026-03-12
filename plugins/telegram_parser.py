"""
Telegram Message Parser Plugin — XtractR Forensic Platform
Extracts messages and user metadata from Android Telegram cache4.db.
"""
import sqlite3
import tempfile
import os
import logging
from typing import List, Dict, Any
from core.plugin_interface import BasePlugin, Artifact
from core.vfs.base import BaseVFS

logger = logging.getLogger("xtractr.plugin.telegram")

TELEGRAM_DB_NAMES = {"cache4.db", "cache2.db"}


class TelegramParser(BasePlugin):
    NAME = "Telegram Parser"
    VERSION = "1.0.0"
    DESCRIPTION = "Extracts Telegram messages and user info from cache4.db"

    def can_parse(self, vfs: BaseVFS) -> bool:
        return True

    def parse(self, vfs: BaseVFS, context: Dict[str, Any]) -> List[Artifact]:
        artifacts = []

        candidates = []
        for root, dirs, files in vfs.walk(""):
            for f in files:
                if f in TELEGRAM_DB_NAMES:
                    candidates.append(os.path.join(root, f))

        for db_path in candidates:
            try:
                with tempfile.NamedTemporaryFile(suffix=".db", delete=True) as tmp:
                    tmp.write(vfs.read_bytes(db_path))
                    tmp.flush()

                    conn = sqlite3.connect(tmp.name)
                    conn.row_factory = sqlite3.Row
                    cursor = conn.cursor()

                    tables = {row[0] for row in cursor.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    ).fetchall()}

                    # User contacts
                    if "users" in tables:
                        try:
                            cursor.execute("SELECT uid, name FROM users")
                            for row in cursor.fetchall():
                                name = row["name"] or "Unknown"
                                artifacts.append(Artifact(
                                    artifact_id=f"tg_user_{row['uid']}",
                                    artifact_type="TELEGRAM_CONTACT",
                                    source_path=db_path,
                                    timestamp_utc=0,
                                    parser_name=self.NAME,
                                    parser_version=self.VERSION,
                                    actor=str(row["uid"]),
                                    details={"name": name, "uid": row["uid"]},
                                ))
                        except sqlite3.OperationalError as e:
                            logger.debug(f"[Telegram] users query failed: {e}")

                    # Messages
                    if "messages" in tables:
                        try:
                            # Telegram stores messages as BLOBs in some versions;
                            # on others, fields like mid, uid, date, data exist.
                            cursor.execute("""
                                SELECT mid, uid, date, data, read_state, send_state, out
                                FROM messages ORDER BY date ASC
                            """)
                            for row in cursor.fetchall():
                                ts = self.normalize_timestamp(row["date"])
                                # Telegram date is seconds — normalize expects ms
                                if ts > 0 and ts < 2_000_000_000:  # looks like seconds
                                    ts = ts * 1000

                                raw_data = row["data"]
                                body = ""
                                if isinstance(raw_data, str):
                                    body = raw_data[:4096]
                                elif isinstance(raw_data, bytes):
                                    body = f"[BLOB:{len(raw_data)} bytes]"

                                direction = "SENT" if row["out"] == 1 else "RECEIVED"

                                artifacts.append(Artifact(
                                    artifact_id=f"tg_msg_{row['mid']}_{row['uid']}",
                                    artifact_type="TELEGRAM_MSG",
                                    source_path=db_path,
                                    timestamp_utc=ts,
                                    parser_name=self.NAME,
                                    parser_version=self.VERSION,
                                    actor=str(row["uid"]),
                                    details={
                                        "body": body,
                                        "direction": direction,
                                        "read_state": row["read_state"],
                                        "send_state": row["send_state"],
                                    },
                                ))
                        except sqlite3.OperationalError as e:
                            logger.warning(f"[Telegram] messages query failed on {db_path}: {e}")

                    # media_v4 — media stubs
                    if "media_v4" in tables:
                        try:
                            cursor.execute("""
                                SELECT mid, uid, date, type, data
                                FROM media_v4 ORDER BY date ASC
                            """)
                            for row in cursor.fetchall():
                                ts = self.normalize_timestamp(row["date"])
                                if ts > 0 and ts < 2_000_000_000:
                                    ts = ts * 1000

                                media_type_map = {
                                    0: "PHOTO", 1: "VIDEO", 2: "DOCUMENT",
                                    3: "AUDIO", 4: "VOICE", 5: "STICKER",
                                    6: "GIF", 8: "MUSIC",
                                }
                                mt = media_type_map.get(row["type"], f"TYPE_{row['type']}")

                                artifacts.append(Artifact(
                                    artifact_id=f"tg_media_{row['mid']}_{row['uid']}",
                                    artifact_type="TELEGRAM_MEDIA",
                                    source_path=db_path,
                                    timestamp_utc=ts,
                                    parser_name=self.NAME,
                                    parser_version=self.VERSION,
                                    actor=str(row["uid"]),
                                    details={"media_type": mt},
                                ))
                        except sqlite3.OperationalError as e:
                            logger.debug(f"[Telegram] media_v4 query failed: {e}")

                    conn.close()
            except Exception as e:
                logger.warning(f"[Telegram] Failed to process {db_path}: {e}")

        return artifacts
