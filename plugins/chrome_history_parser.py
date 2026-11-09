"""
Chrome/WebView History Parser Plugin — XtractR Forensic Platform
Extracts browsing history, downloads, and bookmarks from Chromium-based browsers.
"""
import sqlite3
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
                with self.open_evidence_db(vfs, db_path) as conn:
                    cursor = conn.cursor()

                    # URLs / Visits
                    try:
                        columns = {row[1] for row in cursor.execute("PRAGMA table_info(urls)").fetchall()}
                        if not columns or "url" not in columns:
                            raise sqlite3.OperationalError("unsupported urls table schema")
                        fields = [name for name in ("url", "title", "visit_count", "last_visit_time") if name in columns]
                        cursor.execute("SELECT " + ", ".join(fields) + " FROM urls")
                        for row in cursor.fetchall():
                            try:
                                record = dict(row)
                                ts_utc = webkit_to_unix_ms(record.get("last_visit_time", 0))
                                artifacts.append(Artifact(
                                    artifact_id=f"web_{ts_utc}_{self.derive_artifact_id('web', record['url'])}",
                                    artifact_type="WEB_HISTORY",
                                    source_path=db_path,
                                    timestamp_utc=ts_utc,
                                    parser_name=self.NAME,
                                    parser_version=self.VERSION,
                                    actor="DEVICE",
                                    details={
                                        "url": record["url"],
                                        "title": record.get("title") or "",
                                        "visit_count": record.get("visit_count", 0),
                                    },
                                ))
                            except Exception as e:
                                self.errors.append(f"Web history row parse failed: {e}")
                    except sqlite3.OperationalError as e:
                        logger.warning(f"urls table query failed on {db_path}: {e}")
                        self.errors.append(f"urls table query failed: {e}")

                    # Downloads
                    try:
                        cursor.execute("""
                            SELECT target_path, tab_url, total_bytes, start_time, end_time,
                                   state, danger_type, mime_type
                            FROM downloads
                        """)
                        for row in cursor.fetchall():
                            try:
                                ts_utc = webkit_to_unix_ms(row["start_time"])
                                artifacts.append(Artifact(
                                    artifact_id=f"download_{ts_utc}_{self.derive_artifact_id('dl', row['target_path'] or '')}",
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
                            except Exception as e:
                                self.errors.append(f"Download row parse failed: {e}")
                    except sqlite3.OperationalError as e:
                        logger.debug(f"downloads table query failed on {db_path}: {e}")

            except Exception as e:
                logger.warning(f"Failed to process {db_path}: {e}")
                self.errors.append(f"Failed to process {db_path}: {e}")

        return artifacts
