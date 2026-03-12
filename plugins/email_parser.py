"""
Email Parser Plugin — XtractR Forensic Platform
Extracts emails from Android Gmail cache (EmailProvider.db) and standalone .eml files.
"""
import sqlite3
import tempfile
import os
import email
import email.policy
import logging
from typing import List, Dict, Any
from core.plugin_interface import BasePlugin, Artifact
from core.vfs.base import BaseVFS

logger = logging.getLogger("xtractr.plugin.email")

EMAIL_DB_NAMES = {"EmailProvider.db", "mailbox.db", "EmailProviderBody.db"}


class EmailParser(BasePlugin):
    NAME = "Email Parser"
    VERSION = "1.0.0"
    DESCRIPTION = "Extracts emails from Android Gmail/Email cache and .eml files"

    def can_parse(self, vfs: BaseVFS) -> bool:
        return True

    def parse(self, vfs: BaseVFS, context: Dict[str, Any]) -> List[Artifact]:
        artifacts = []

        db_candidates = []
        eml_files = []

        for root, dirs, files in vfs.walk(""):
            for f in files:
                if f in EMAIL_DB_NAMES:
                    db_candidates.append(os.path.join(root, f))
                elif f.lower().endswith(".eml"):
                    eml_files.append(os.path.join(root, f))

        # Parse email databases
        for db_path in db_candidates:
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

                    # Standard Android EmailProvider schema
                    if "Message" in tables:
                        try:
                            cursor.execute("""
                                SELECT _id, subject, fromList, toList, timeStamp,
                                       flagRead, snippet
                                FROM Message ORDER BY timeStamp ASC
                            """)
                            for row in cursor.fetchall():
                                ts = self.normalize_timestamp(row["timeStamp"])
                                artifacts.append(Artifact(
                                    artifact_id=f"email_db_{row['_id']}",
                                    artifact_type="EMAIL",
                                    source_path=db_path,
                                    timestamp_utc=ts,
                                    parser_name=self.NAME,
                                    parser_version=self.VERSION,
                                    actor=str(row["fromList"] or "unknown"),
                                    details={
                                        "subject": row["subject"] or "",
                                        "from": row["fromList"] or "",
                                        "to": row["toList"] or "",
                                        "snippet": (row["snippet"] or "")[:512],
                                        "read": bool(row["flagRead"]),
                                    },
                                ))
                        except sqlite3.OperationalError as e:
                            logger.warning(f"[EmailParser] Message table query failed on {db_path}: {e}")

                    # Gmail conversations table (some versions)
                    if "conversations" in tables:
                        try:
                            cursor.execute("""
                                SELECT _id, subject, snippet, fromAddress,
                                       dateMs, numMessages
                                FROM conversations ORDER BY dateMs ASC
                            """)
                            for row in cursor.fetchall():
                                ts = self.normalize_timestamp(row["dateMs"])
                                artifacts.append(Artifact(
                                    artifact_id=f"gmail_conv_{row['_id']}",
                                    artifact_type="EMAIL_THREAD",
                                    source_path=db_path,
                                    timestamp_utc=ts,
                                    parser_name=self.NAME,
                                    parser_version=self.VERSION,
                                    actor=str(row["fromAddress"] or "unknown"),
                                    details={
                                        "subject": row["subject"] or "",
                                        "snippet": (row["snippet"] or "")[:512],
                                        "num_messages": row["numMessages"],
                                    },
                                ))
                        except sqlite3.OperationalError as e:
                            logger.debug(f"[EmailParser] conversations query failed: {e}")

                    conn.close()
            except Exception as e:
                logger.warning(f"[EmailParser] Failed to process {db_path}: {e}")

        # Parse standalone .eml files (RFC 2822)
        for eml_path in eml_files:
            try:
                raw_bytes = vfs.read_bytes(eml_path)
                msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)

                from_addr = str(msg.get("From", ""))
                to_addr = str(msg.get("To", ""))
                subject = str(msg.get("Subject", ""))
                date_str = str(msg.get("Date", ""))

                # Try to parse date
                ts = 0
                try:
                    from email.utils import parsedate_to_datetime
                    dt = parsedate_to_datetime(date_str)
                    ts = int(dt.timestamp() * 1000)
                except Exception:
                    pass

                # Extract text body snippet
                body_snippet = ""
                if msg.is_multipart():
                    for part in msg.iter_parts():
                        ct = part.get_content_type()
                        if ct == "text/plain":
                            try:
                                body_snippet = part.get_content()[:512]
                            except Exception:
                                pass
                            break
                else:
                    try:
                        body_snippet = msg.get_content()[:512]
                    except Exception:
                        pass

                artifacts.append(Artifact(
                    artifact_id=f"eml_{abs(hash(eml_path))}",
                    artifact_type="EMAIL",
                    source_path=eml_path,
                    timestamp_utc=ts,
                    parser_name=self.NAME,
                    parser_version=self.VERSION,
                    actor=from_addr,
                    details={
                        "subject": subject,
                        "from": from_addr,
                        "to": to_addr,
                        "date_raw": date_str,
                        "body_snippet": body_snippet,
                    },
                ))
            except Exception as e:
                logger.warning(f"[EmailParser] Failed to parse .eml {eml_path}: {e}")

        return artifacts
