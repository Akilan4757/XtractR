"""
Chrome/WebView History Parser Plugin — XtractR Forensic Platform
Extracts browsing history, downloads, and bookmarks from Chromium-based browsers.
"""
import sqlite3
import tempfile
import os
import logging
from typing import List, Dict, Any
from core.plugin_interface import BasePlugin, Artifact
from core.vfs.base import BaseVFS
from datetime import datetime, timedelta

logger = logging.getLogger("xtractr.plugin.chrome")

# WebKit / Chrome timestamp epoch
WEBKIT_EPOCH = datetime(1601, 1, 1)


def webkit_to_unix_ms(ts_webkit: int) -> int:
    """Convert WebKit microseconds-since-1601 to Unix milliseconds."""
    if not ts_webkit or ts_webkit <= 0:
        return 0
    try:
        ts_obj = WEBKIT_EPOCH + timedelta(microseconds=int(ts_webkit))
        return int(ts_obj.timestamp() * 1000)
    except (OverflowError, OSError, ValueError):
        return 0


class ChromeHistoryParser(BasePlugin):
    NAME = "Chrome History Parser"
    VERSION = "1.1.0"
    DESCRIPTION = "Extracts Web History, Downloads, and Bookmarks from Chrome/WebView DB"

    def can_parse(self, vfs: BaseVFS) -> bool:
        return True

    def parse(self, vfs: BaseVFS, context: Dict[str, Any]) -> List[Artifact]:
        artifacts = []
        candidates = []
        for root, dirs, files in vfs.walk(""):
            if "History" in files:
                candidates.append(os.path.join(root, "History"))

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

                    # URLs / Visits
                    try:
                        cursor.execute("SELECT url, title, visit_count, last_visit_time FROM urls")
                        for row in cursor.fetchall():
                            ts_utc = webkit_to_unix_ms(row["last_visit_time"])
                            artifacts.append(Artifact(
                                artifact_id=f"web_{ts_utc}_{abs(hash(row['url']))}",
                                artifact_type="WEB_HISTORY",
                                source_path=db_path,
                                timestamp_utc=ts_utc,
                                parser_name=self.NAME,
                                parser_version=self.VERSION,
                                actor="DEVICE",
                                details={
                                    "url": row["url"],
                                    "title": row["title"] or "",
                                    "visit_count": row["visit_count"],
                                },
                            ))
                    except sqlite3.OperationalError as e:
                        logger.warning(f"[ChromeParser] urls table query failed on {db_path}: {e}")

                    # Downloads
                    try:
                        cursor.execute("""
                            SELECT target_path, tab_url, total_bytes, start_time, end_time,
                                   state, danger_type, mime_type
                            FROM downloads
                        """)
                        for row in cursor.fetchall():
                            ts_utc = webkit_to_unix_ms(row["start_time"])
                            artifacts.append(Artifact(
                                artifact_id=f"download_{ts_utc}_{abs(hash(row['target_path'] or ''))}",
                                artifact_type="WEB_DOWNLOAD",
                                source_path=db_path,
                                timestamp_utc=ts_utc,
                                parser_name=self.NAME,
                                parser_version=self.VERSION,
                                actor="DEVICE",
                                details={
                                    "target_path": row["target_path"] or "",
                                    "tab_url": row["tab_url"] or "",
                                    "total_bytes": row["total_bytes"],
                                    "mime_type": row["mime_type"] or "",
                                    "state": row["state"],
                                    "danger_type": row["danger_type"],
                                },
                            ))
                    except sqlite3.OperationalError as e:
                        logger.debug(f"[ChromeParser] downloads table not available in {db_path}: {e}")

                    conn.close()
            except Exception as e:
                logger.warning(f"[ChromeParser] Failed to process {db_path}: {e}")

        return artifacts
