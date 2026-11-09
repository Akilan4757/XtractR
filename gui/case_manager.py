"""
XtractR GUI — Case Manager
Thin wrapper around core/ modules providing progress-callback-aware pipeline execution.
"""
import os
import json
import sqlite3
import logging
import threading
import time
import uuid
from typing import Optional, Callable, Dict, Any, List

logger = logging.getLogger("xtractr.gui.case_manager")


class CaseInfo:
    """Lightweight case metadata container."""
    def __init__(self, case_dir: str):
        self.case_dir = os.path.abspath(case_dir)
        self.db_path = os.path.join(self.case_dir, "case.db")
        self.keys_dir = os.path.join(self.case_dir, "keys")
        self._meta_cache: Dict[str, str] = {}
        self._load_metadata()

    def _load_metadata(self):
        if not os.path.exists(self.db_path):
            return
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT key, value FROM case_metadata")
            self._meta_cache = {row[0]: row[1] for row in cursor.fetchall()}
            conn.close()
        except Exception as e:
            logger.warning(f"Failed to load metadata for {self.case_dir}: {e}")

    @property
    def case_id(self) -> str:
        return self._meta_cache.get("case_id", "UNKNOWN")

    @property
    def investigator(self) -> str:
        return self._meta_cache.get("investigator_name", "Unknown")

    @property
    def source_path(self) -> Optional[str]:
        return self._meta_cache.get("source_path")

    @property
    def exists(self) -> bool:
        return os.path.exists(self.db_path)

    def pipeline_stage(self) -> str:
        """Determine the furthest completed pipeline stage."""
        if not self.exists:
            return "none"
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Check for export
            exports_dir = os.path.join(self.case_dir, "exports")
            if os.path.isdir(exports_dir) and any(f.endswith(".zip") for f in os.listdir(exports_dir)):
                conn.close()
                return "exported"

            # Check for report
            if os.path.exists(os.path.join(self.case_dir, "report.html")):
                conn.close()
                return "reported"

            # Check for correlation
            if os.path.exists(os.path.join(self.case_dir, "correlation.json")):
                conn.close()
                return "processed"

            # Check for artifacts
            cursor.execute("SELECT COUNT(*) FROM derived_artifacts")
            if cursor.fetchone()[0] > 0:
                conn.close()
                return "plugins_done"

            # Check for baseline
            cursor.execute("SELECT COUNT(*) FROM baseline_files")
            if cursor.fetchone()[0] > 0:
                conn.close()
                return "scanned"

            # Check for source
            if self.source_path:
                conn.close()
                return "ingested"

            conn.close()
            return "initialized"
        except Exception:
            return "initialized"

    def get_artifact_count(self) -> int:
        if not self.exists:
            return 0
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM derived_artifacts")
            count = cursor.fetchone()[0]
            conn.close()
            return count
        except Exception:
            return 0

    def get_event_count(self) -> int:
        if not self.exists:
            return 0
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM custody_events")
            count = cursor.fetchone()[0]
            conn.close()
            return count
        except Exception:
            return 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_dir": self.case_dir,
            "case_id": self.case_id,
            "investigator": self.investigator,
            "source_path": self.source_path,
            "stage": self.pipeline_stage(),
            "artifact_count": self.get_artifact_count(),
            "event_count": self.get_event_count(),
        }


class CaseManager:
    """
    Manages case discovery and pipeline execution with progress streaming.
    """

    def __init__(self, cases_root: str):
        self.cases_root = os.path.abspath(cases_root)
        os.makedirs(self.cases_root, exist_ok=True)
        self._running_tasks: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    def list_cases(self) -> List[Dict[str, Any]]:
        """Discover all case directories under cases_root."""
        cases = []
        if not os.path.isdir(self.cases_root):
            return cases
        for entry in os.listdir(self.cases_root):
            case_dir = os.path.join(self.cases_root, entry)
            if os.path.isdir(case_dir) and os.path.exists(os.path.join(case_dir, "case.db")):
                try:
                    info = CaseInfo(case_dir)
                    cases.append(info.to_dict())
                except Exception as e:
                    logger.warning(f"Skipping {case_dir}: {e}")
        return cases

    def get_case(self, case_id: str) -> Optional[CaseInfo]:
        """Find a case by its case_id."""
        for entry in os.listdir(self.cases_root):
            case_dir = os.path.join(self.cases_root, entry)
            db_path = os.path.join(case_dir, "case.db")
            if os.path.isdir(case_dir) and os.path.exists(db_path):
                try:
                    conn = sqlite3.connect(db_path)
                    cursor = conn.cursor()
                    cursor.execute("SELECT value FROM case_metadata WHERE key='case_id'")
                    row = cursor.fetchone()
                    conn.close()
                    if row and row[0] == case_id:
                        return CaseInfo(case_dir)
                except Exception:
                    continue
        return None

    def get_case_by_dir(self, case_dir: str) -> Optional[CaseInfo]:
        """Get case info by absolute directory path."""
        full_path = os.path.abspath(case_dir)
        if os.path.exists(os.path.join(full_path, "case.db")):
            return CaseInfo(full_path)
        return None

    # ── Pipeline operations ──────────────────────────────────────

    def init_case(self, case_id: str, investigator_name: str, passphrase: str,
                  progress_cb: Optional[Callable] = None) -> Dict[str, Any]:
        """Create a new case."""
        from core.database import CaseDatabase
        from core.crypto import IdentityManager
        from core.environment import log_environment

        case_dir = os.path.join(self.cases_root, case_id)
        if os.path.exists(case_dir):
            return {"success": False, "error": f"Case directory already exists: {case_id}"}

        try:
            if progress_cb:
                progress_cb("Creating case directory...")
            os.makedirs(case_dir)

            if progress_cb:
                progress_cb("Generating cryptographic identity...")
            id_mgr = IdentityManager(os.path.join(case_dir, "keys"))
            passphrase_bytes = passphrase.encode("utf-8") if passphrase else None
            id_mgr.load_or_generate_keys(passphrase_bytes)

            if progress_cb:
                progress_cb("Initializing case database...")
            db = CaseDatabase(os.path.join(case_dir, "case.db"))
            db.set_metadata("case_id", case_id)
            db.set_metadata("investigator_name", investigator_name)
            db.log_event("CASE_INIT", f"Initialized Case {case_id} by {investigator_name}", actor="USER")

            log_environment(db)
            db.close()

            if progress_cb:
                progress_cb(f"Case {case_id} initialized successfully.")

            return {"success": True, "case_dir": case_dir}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def ingest_evidence(self, case_id: str, source_path: str, passphrase: str,
                        progress_cb: Optional[Callable] = None) -> Dict[str, Any]:
        """Link evidence source to case."""
        from core.database import CaseDatabase
        from core.crypto import IdentityManager

        case_info = self.get_case(case_id)
        if not case_info:
            return {"success": False, "error": f"Case not found: {case_id}"}

        abs_source = os.path.abspath(source_path)
        if not os.path.exists(abs_source):
            return {"success": False, "error": f"Source path not found: {source_path}"}

        db = None
        try:
            db = CaseDatabase(case_info.db_path)
            id_mgr = IdentityManager(case_info.keys_dir)
            passphrase_bytes = passphrase.encode("utf-8") if passphrase else None
            if not id_mgr.load_or_generate_keys(passphrase_bytes):
                db.close()
                db = None
                return {"success": False, "error": "Wrong passphrase or corrupt keys"}

            if progress_cb:
                progress_cb(f"Linking evidence: {abs_source}")

            db.set_metadata("source_path", abs_source)
            db.log_event("EVIDENCE_ACQUIRED", f"Source: {abs_source}")
            db.close()
            db = None

            if progress_cb:
                progress_cb("Evidence linked successfully.")

            return {"success": True}
        except Exception as e:
            if db is not None:
                db.close()
            return {"success": False, "error": str(e)}

    def run_scan(self, case_id: str, passphrase: str,
                 progress_cb: Optional[Callable] = None) -> Dict[str, Any]:
        """Create integrity baseline."""
        from core.database import CaseDatabase
        from core.crypto import IdentityManager
        from core.ingest import get_vfs
        from core.baseline import create_baseline

        case_info = self.get_case(case_id)
        if not case_info:
            return {"success": False, "error": f"Case not found: {case_id}"}

        db = None
        try:
            db = CaseDatabase(case_info.db_path)
            id_mgr = IdentityManager(case_info.keys_dir)
            passphrase_bytes = passphrase.encode("utf-8") if passphrase else None
            if not id_mgr.load_or_generate_keys(passphrase_bytes):
                db.close()
                db = None
                return {"success": False, "error": "Wrong passphrase or corrupt keys"}

            src = db.get_metadata("source_path")
            if not src:
                db.close()
                db = None
                return {"success": False, "error": "No evidence linked. Run ingest first."}

            if progress_cb:
                progress_cb("Creating VFS for evidence source...")
            vfs = get_vfs(src)

            if progress_cb:
                progress_cb("Computing integrity baseline (hashing all files)...")
            create_baseline(vfs, db)

            db.close()
            db = None
            if progress_cb:
                progress_cb("Baseline scan complete.")
            return {"success": True}
        except Exception as e:
            if db is not None:
                db.close()
            return {"success": False, "error": str(e)}

    def run_plugins(self, case_id: str, passphrase: str,
                    progress_cb: Optional[Callable] = None) -> Dict[str, Any]:
        """Execute all parser plugins."""
        from core.database import CaseDatabase
        from core.crypto import IdentityManager
        from core.ingest import get_vfs
        from core.plugin_engine import PluginEngine

        case_info = self.get_case(case_id)
        if not case_info:
            return {"success": False, "error": f"Case not found: {case_id}"}

        try:
            db = CaseDatabase(case_info.db_path)
            id_mgr = IdentityManager(case_info.keys_dir)
            passphrase_bytes = passphrase.encode("utf-8") if passphrase else None
            if not id_mgr.load_or_generate_keys(passphrase_bytes):
                db.close()
                return {"success": False, "error": "Wrong passphrase or corrupt keys"}

            src = db.get_metadata("source_path")
            if not src:
                db.close()
                return {"success": False, "error": "No evidence linked."}

            vfs = get_vfs(src)
            plugin_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "plugins")

            if progress_cb:
                progress_cb(f"Loading plugins from {plugin_dir}...")

            engine = PluginEngine(plugin_dir, db)

            if progress_cb:
                progress_cb("Running all plugins (this may take a while)...")

            engine.run_all(vfs)

            # Count artifacts
            cursor = db._conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM derived_artifacts")
            count = cursor.fetchone()[0]

            db.close()

            if progress_cb:
                progress_cb(f"Plugin execution complete. {count} artifacts extracted.")

            return {"success": True, "artifact_count": count}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def run_processing(self, case_id: str, passphrase: str,
                       progress_cb: Optional[Callable] = None) -> Dict[str, Any]:
        """Run timeline and correlation."""
        from core.database import CaseDatabase
        from core.crypto import IdentityManager
        from core.timeline import TimelineEngine
        from core.correlation import CorrelationEngine
        from core.integrity import canonical_json

        case_info = self.get_case(case_id)
        if not case_info:
            return {"success": False, "error": f"Case not found: {case_id}"}

        try:
            db = CaseDatabase(case_info.db_path)
            id_mgr = IdentityManager(case_info.keys_dir)
            passphrase_bytes = passphrase.encode("utf-8") if passphrase else None
            if not id_mgr.load_or_generate_keys(passphrase_bytes):
                db.close()
                return {"success": False, "error": "Wrong passphrase or corrupt keys"}

            if progress_cb:
                progress_cb("Building timeline...")
            tl_engine = TimelineEngine(db, case_info.case_dir)
            tl_engine.build_timeline()

            if progress_cb:
                progress_cb("Running correlations...")
            corr_engine = CorrelationEngine(db)
            results = corr_engine.run_correlations()

            corr_path = os.path.join(case_info.case_dir, "correlation.json")
            with open(corr_path, "wb") as f:
                f.write(canonical_json(results))

            db.log_event("PROCESSING_COMPLETE", "Timeline and Correlation finished")
            db.close()

            if progress_cb:
                progress_cb("Timeline and correlation processing complete.")

            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def generate_report(self, case_id: str, passphrase: str,
                        progress_cb: Optional[Callable] = None) -> Dict[str, Any]:
        """Generate HTML report."""
        from core.database import CaseDatabase
        from core.crypto import IdentityManager
        from core.reporting import generate_report

        case_info = self.get_case(case_id)
        if not case_info:
            return {"success": False, "error": f"Case not found: {case_id}"}

        try:
            db = CaseDatabase(case_info.db_path)
            id_mgr = IdentityManager(case_info.keys_dir)
            passphrase_bytes = passphrase.encode("utf-8") if passphrase else None
            if not id_mgr.load_or_generate_keys(passphrase_bytes):
                db.close()
                return {"success": False, "error": "Wrong passphrase or corrupt keys"}

            if progress_cb:
                progress_cb("Generating forensic report...")

            generate_report(db, case_info.case_dir)
            db.log_event("REPORT_GENERATED", "HTML Report created")
            db.close()

            if progress_cb:
                progress_cb("Report generated successfully.")

            return {"success": True, "report_path": os.path.join(case_info.case_dir, "report.html")}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def create_export(self, case_id: str, passphrase: str,
                      include_evidence: bool = True,
                      progress_cb: Optional[Callable] = None) -> Dict[str, Any]:
        """Create sealed export bundle."""
        from core.database import CaseDatabase
        from core.crypto import IdentityManager
        from core.export import ExportManager

        case_info = self.get_case(case_id)
        if not case_info:
            return {"success": False, "error": f"Case not found: {case_id}"}

        db = None
        try:
            db = CaseDatabase(case_info.db_path)
            id_mgr = IdentityManager(case_info.keys_dir)
            passphrase_bytes = passphrase.encode("utf-8") if passphrase else None
            if not id_mgr.load_or_generate_keys(passphrase_bytes):
                db.close()
                db = None
                return {"success": False, "error": "Wrong passphrase or corrupt keys"}

            if progress_cb:
                progress_cb("Creating sealed export bundle...")

            exporter = ExportManager(db, id_mgr, case_info.case_dir)
            bundle_path = exporter.create_bundle(include_evidence=include_evidence, progress_cb=progress_cb)

            db.close()
            db = None

            if progress_cb:
                progress_cb(f"Export bundle created: {os.path.basename(bundle_path)}")

            readme_path = os.path.join(case_info.case_dir, "README_EVIDENCE.md")
            return {"success": True, "bundle_path": bundle_path,
                    "evidence_readme_path": readme_path if os.path.exists(readme_path) else None}
        except Exception as e:
            if db is not None:
                db.close()
            return {"success": False, "error": str(e)}

        except SystemExit as exc:
            if db is not None:
                db.close()
            return {"success": False, "error": "Evidence integrity failed; export was aborted.",
                    "exit_code": exc.code}

    # ── Query helpers ────────────────────────────────────────────

    def get_artifacts(self, case_id: str, artifact_type: Optional[str] = None,
                      actor: Optional[str] = None, search: Optional[str] = None,
                      page: int = 1, per_page: int = 50) -> Dict[str, Any]:
        """Query artifacts with filtering and pagination."""
        case_info = self.get_case(case_id)
        if not case_info:
            return {"success": False, "error": "Case not found"}

        try:
            conn = sqlite3.connect(case_info.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            where_clauses = []
            params = []

            if artifact_type:
                where_clauses.append("artifact_type = ?")
                params.append(artifact_type)
            if actor:
                where_clauses.append("actor LIKE ?")
                params.append(f"%{actor}%")
            if search:
                where_clauses.append("(details LIKE ? OR source_path LIKE ? OR actor LIKE ?)")
                params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])

            where = " AND ".join(where_clauses) if where_clauses else "1=1"

            # Count
            cursor.execute(f"SELECT COUNT(*) FROM derived_artifacts WHERE {where}", params)
            total = cursor.fetchone()[0]

            # Fetch page
            offset = (page - 1) * per_page
            cursor.execute(
                f"SELECT * FROM derived_artifacts WHERE {where} ORDER BY timestamp_utc DESC LIMIT ? OFFSET ?",
                params + [per_page, offset]
            )
            rows = cursor.fetchall()

            artifacts = []
            for row in rows:
                art = dict(row)
                # Parse details JSON
                try:
                    art["details"] = json.loads(art["details"]) if isinstance(art["details"], str) else art["details"]
                except Exception:
                    art["details"] = {"_raw": str(art.get("details", ""))}
                artifacts.append(art)

            # Get distinct types for filter dropdown
            cursor.execute("SELECT DISTINCT artifact_type FROM derived_artifacts ORDER BY artifact_type")
            types = [r[0] for r in cursor.fetchall()]

            conn.close()

            return {
                "success": True,
                "artifacts": artifacts,
                "total": total,
                "page": page,
                "per_page": per_page,
                "total_pages": max(1, (total + per_page - 1) // per_page),
                "artifact_types": types,
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def get_timeline(self, case_id: str) -> Dict[str, Any]:
        """Get timeline data."""
        case_info = self.get_case(case_id)
        if not case_info:
            return {"success": False, "error": "Case not found"}

        timeline_path = os.path.join(case_info.case_dir, "timeline.csv")
        if not os.path.exists(timeline_path):
            return {"success": False, "error": "Timeline not generated yet. Run 'process' first."}

        try:
            entries = []
            with open(timeline_path, "r", encoding="utf-8") as f:
                import csv
                reader = csv.DictReader(f)
                for i, row in enumerate(reader):
                    if i >= 2000:  # Cap for browser performance
                        break
                    entries.append(row)

            # Load correlation data if available
            correlation = {}
            corr_path = os.path.join(case_info.case_dir, "correlation.json")
            if os.path.exists(corr_path):
                with open(corr_path, "r", encoding="utf-8") as f:
                    correlation = json.load(f)

            return {"success": True, "entries": entries, "correlation": correlation}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def get_custody_log(self, case_id: str) -> Dict[str, Any]:
        """Get chain-of-custody events."""
        case_info = self.get_case(case_id)
        if not case_info:
            return {"success": False, "error": "Case not found"}

        try:
            conn = sqlite3.connect(case_info.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM custody_events ORDER BY id ASC")
            events = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return {"success": True, "events": events}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def get_artifact_stats(self, case_id: str) -> Dict[str, Any]:
        """Get artifact type distribution for dashboard charts."""
        case_info = self.get_case(case_id)
        if not case_info:
            return {"success": False, "error": "Case not found"}

        try:
            conn = sqlite3.connect(case_info.db_path)
            cursor = conn.cursor()
            cursor.execute(
                "SELECT artifact_type, COUNT(*) as cnt FROM derived_artifacts GROUP BY artifact_type ORDER BY cnt DESC"
            )
            stats = {row[0]: row[1] for row in cursor.fetchall()}

            # Plugin run stats
            cursor.execute(
                "SELECT plugin_name, status, artifacts_count FROM plugin_runs ORDER BY start_time ASC"
            )
            plugin_runs = [{"name": r[0], "status": r[1], "count": r[2]} for r in cursor.fetchall()]

            conn.close()
            return {"success": True, "type_distribution": stats, "plugin_runs": plugin_runs}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def verify_case(self, case_id: str, expected_fingerprint: str = "",
                    check_evidence: bool = True) -> Dict[str, Any]:
        """Run verification checks and return actionable, location-aware findings."""
        case_info = self.get_case(case_id)
        if not case_info:
            return {"success": False, "error": "Case not found"}

        pub_key_path = os.path.join(case_info.case_dir, "keys", "investigator.pub")
        if not os.path.exists(pub_key_path):
            pub_key_path = os.path.join(case_info.case_dir, "investigator.pub")

        if not os.path.exists(pub_key_path):
            return {
                "success": False,
                "error": "Investigator public key not found. Ensure keys have been generated/exported."
            }

        import contextlib
        import io
        import xtractr_verify

        steps = []
        def add_step(check_id, name, status, message, location=None, issues=None):
            steps.append({"id": check_id, "name": name, "status": status,
                          "message": message, "location": location,
                          "issues": issues or []})
        try:
            # Database physical integrity
            conn = sqlite3.connect(case_info.db_path)
            cursor = conn.cursor()
            cursor.execute("PRAGMA integrity_check")
            integrity_rows = [row[0] for row in cursor.fetchall()]
            conn.close()
            db_ok = integrity_rows == ["ok"]
            add_step("sqlite", "SQLite database integrity", "passed" if db_ok else "failed",
                     "Database pages and indexes are consistent." if db_ok else "SQLite reported corruption.",
                     "case.db", [] if db_ok else [{"location": "case.db", "expected": "ok", "actual": "; ".join(integrity_rows)}])

            # Chained ledger with first failing event location
            ledger_issues = []
            conn = sqlite3.connect(case_info.db_path)
            rows = conn.execute("SELECT id,timestamp_utc,action,details,source_hash,prev_event_hash,this_event_hash,actor FROM custody_events ORDER BY id").fetchall()
            conn.close()
            previous = "GENESIS_HASH_00000000000000000000000000000000"
            import hashlib
            for row in rows:
                event_id, ts, action, details, source_hash, prev_hash, event_hash, actor = row
                payload = f"{ts}|{action}|{details}|{source_hash}|{previous}|{actor}".encode("utf-8")
                calculated = hashlib.sha256(payload).hexdigest()
                if prev_hash != previous:
                    ledger_issues.append({"location": f"case.db / custody_events.id={event_id}", "expected": previous, "actual": prev_hash, "message": "Previous-event link does not match."})
                    break
                if event_hash != calculated:
                    ledger_issues.append({"location": f"case.db / custody_events.id={event_id}", "expected": calculated, "actual": event_hash, "message": "Event hash does not match its fields."})
                    break
                previous = event_hash
            add_step("ledger", "Custody event hash chain", "failed" if ledger_issues else "passed",
                     f"Checked {len(rows)} custody events." if not ledger_issues else "First broken ledger link is shown below.",
                     "case.db / custody_events", ledger_issues)

            # Seal structure, Merkle roots, and investigator signature
            capture = io.StringIO()
            with contextlib.redirect_stdout(capture):
                seal_ok, code, reason = xtractr_verify.verify_merkle_seal(case_info.case_dir, pub_key_path)
            add_step("seal", "Seal, Merkle roots, counts, and signature", "passed" if seal_ok else "failed",
                     "Seal checks passed using the supplied public key." if seal_ok else f"Seal verification failed (exit {code}): {reason}",
                     "seal.json and case.db", [] if seal_ok else [{"location": "seal.json / case.db", "message": reason, "exit_code": code}])

            # Out-of-band signer pin: a key beside a bundle is not a trust anchor.
            actual_fingerprint = xtractr_verify.compute_public_key_fingerprint(pub_key_path)
            if actual_fingerprint and expected_fingerprint:
                matches = actual_fingerprint.lower().replace(":", "") == expected_fingerprint.strip().lower().replace(":", "")
                add_step("identity", "Investigator identity pin", "passed" if matches else "failed",
                         "Public key matches the fingerprint supplied out of band." if matches else "The public key does not match the expected trusted fingerprint.",
                         pub_key_path, [] if matches else [{"location": pub_key_path, "expected": expected_fingerprint, "actual": actual_fingerprint}])
            else:
                add_step("identity", "Investigator identity pin", "warning",
                         f"Signer is not authenticated. Key fingerprint: {actual_fingerprint or 'unavailable'}. Supply a trusted fingerprint from outside this case.", pub_key_path)

            # JSONL twin is compared against every SQLite event field.
            jsonl_path = next((os.path.join(case_info.case_dir, f) for f in os.listdir(case_info.case_dir) if f.endswith("_custody_ledger.jsonl")), None)
            jsonl_issues = []
            if jsonl_path:
                from itertools import zip_longest
                sentinel = object()
                conn = sqlite3.connect(case_info.db_path)
                db_events = conn.execute("SELECT timestamp_utc,action,details,source_hash,prev_event_hash,this_event_hash,actor FROM custody_events ORDER BY id")
                fields = ("timestamp_utc", "action", "details", "source_hash", "prev_event_hash", "this_event_hash", "actor")
                with open(jsonl_path, "r", encoding="utf-8") as stream:
                    for line_number, (db_event, line) in enumerate(zip_longest(db_events, stream, fillvalue=sentinel), 1):
                        if len(jsonl_issues) >= 100:
                            break
                        if db_event is sentinel or line is sentinel:
                            jsonl_issues.append({"location": f"{os.path.basename(jsonl_path)}:{line_number}", "message": "JSONL and SQLite event counts differ."})
                            break
                        try:
                            json_event = json.loads(line)
                        except json.JSONDecodeError as exc:
                            jsonl_issues.append({"location": f"{os.path.basename(jsonl_path)}:{line_number}", "message": f"Invalid JSON: {exc}"})
                            continue
                        for field, expected_value in zip(fields, db_event):
                            actual_value = json_event.get(field)
                            if str(actual_value) != str(expected_value):
                                jsonl_issues.append({"location": f"{os.path.basename(jsonl_path)}:{line_number} / {field}", "expected": str(expected_value), "actual": str(actual_value), "message": "JSONL field differs from the SQLite event."})
                                if len(jsonl_issues) >= 100:
                                    break
                conn.close()
            jsonl_valid = bool(jsonl_path) and not jsonl_issues
            json_status = "passed" if jsonl_valid else ("warning" if not jsonl_path else "failed")
            add_step("jsonl", "JSONL ledger cross-check", json_status,
                     f"JSONL and SQLite event fields match." if jsonl_valid else ("JSONL ledger copy is not present in this case directory." if not jsonl_path else f"Found {len(jsonl_issues)} mismatch(es); showing the first 100."),
                     jsonl_path or case_info.case_dir,
                     jsonl_issues)

            # Export manifest and each listed deliverable
            manifest_path = os.path.join(case_info.case_dir, "manifest.json")
            manifest_issues = []
            if os.path.exists(manifest_path):
                with open(manifest_path, "rb") as stream:
                    manifest_bytes = stream.read()
                signature_path = manifest_path + ".sig"
                if not os.path.exists(signature_path):
                    manifest_issues.append({"location": "manifest.json.sig", "message": "Manifest signature is missing."})
                else:
                    with open(signature_path, "r", encoding="utf-8") as stream:
                        if not xtractr_verify.verify_signature(pub_key_path, manifest_bytes, stream.read().strip()):
                            manifest_issues.append({"location": "manifest.json.sig", "message": "Manifest signature is invalid."})
                manifest = json.loads(manifest_bytes)
                for name, expected_hash in manifest.get("files", {}).items():
                    target = os.path.abspath(os.path.join(case_info.case_dir, name))
                    if os.path.commonpath([case_info.case_dir, target]) != case_info.case_dir:
                        manifest_issues.append({"location": name, "message": "Unsafe path in manifest."})
                        continue
                    if not os.path.isfile(target):
                        manifest_issues.append({"location": name, "expected": expected_hash, "actual": "missing", "message": "Manifest file is missing."})
                        continue
                    with open(target, "rb") as stream:
                        actual_hash = hashlib.sha256(stream.read()).hexdigest()
                    if actual_hash != expected_hash:
                        manifest_issues.append({"location": name, "expected": expected_hash, "actual": actual_hash, "message": "SHA-256 does not match manifest."})
                add_step("manifest", "Export manifest and deliverable hashes", "failed" if manifest_issues else "passed",
                         f"Checked {len(manifest.get('files', {}))} exported files." if not manifest_issues else f"Found {len(manifest_issues)} manifest problem(s).",
                         "manifest.json", manifest_issues)
            else:
                add_step("manifest", "Export manifest and deliverable hashes", "warning", "No export manifest exists yet; export the case to create one.", "manifest.json")

            # Validate the latest downloadable ZIP itself, including every bundled evidence byte.
            import zipfile
            exports_dir = os.path.join(case_info.case_dir, "exports")
            bundles = [os.path.join(exports_dir, name) for name in os.listdir(exports_dir)
                       if name.lower().endswith(".zip")] if os.path.isdir(exports_dir) else []
            if not bundles:
                add_step("bundle", "Downloadable case bundle", "warning", "No exported ZIP is available yet.", "exports/")
            else:
                bundle_path = max(bundles, key=os.path.getmtime)
                bundle_issues = []
                try:
                    with zipfile.ZipFile(bundle_path, "r") as bundle:
                        bundle_names = set(bundle.namelist())
                        if "manifest.json" not in bundle_names or "manifest.json.sig" not in bundle_names:
                            bundle_issues.append({"location": "manifest.json / manifest.json.sig", "message": "The ZIP is missing its signed manifest."})
                        else:
                            zip_manifest_bytes = bundle.read("manifest.json")
                            zip_manifest = json.loads(zip_manifest_bytes)
                            expected_entries = set(zip_manifest.get("files", {})) | {"manifest.json", "manifest.json.sig"}
                            if not xtractr_verify.verify_signature(pub_key_path, zip_manifest_bytes, bundle.read("manifest.json.sig").decode("utf-8").strip()):
                                bundle_issues.append({"location": "manifest.json.sig", "message": "The ZIP manifest signature is invalid."})
                            for name, expected_hash in zip_manifest.get("files", {}).items():
                                try:
                                    digest = hashlib.sha256()
                                    with bundle.open(name, "r") as member:
                                        for chunk in iter(lambda: member.read(1024 * 1024), b""):
                                            digest.update(chunk)
                                    actual_hash = digest.hexdigest()
                                    if actual_hash != expected_hash:
                                        bundle_issues.append({"location": name, "expected": expected_hash, "actual": actual_hash, "message": "Bundled file hash does not match the signed manifest."})
                                except KeyError:
                                    bundle_issues.append({"location": name, "expected": expected_hash, "actual": "missing", "message": "File listed in signed manifest is missing from the ZIP."})

                            if zip_manifest.get("evidence_payload_included"):
                                if "evidence_manifest.json" not in bundle_names:
                                    bundle_issues.append({"location": "evidence_manifest.json", "message": "Evidence payload is marked included but its hash inventory is missing."})
                                else:
                                    evidence_inventory = json.loads(bundle.read("evidence_manifest.json"))
                                    algorithms = tuple(evidence_inventory.get("hash_algorithms", ("sha256", "sha512", "sha384", "sha1", "md5")))
                                    for record in evidence_inventory.get("files", []):
                                        archive_name = "evidence/" + record["path"].replace("\\", "/")
                                        expected_entries.add(archive_name)
                                        digests = {name: hashlib.new(name, usedforsecurity=name not in ("md5", "sha1")) for name in algorithms}
                                        size = 0
                                        try:
                                            with bundle.open(archive_name, "r") as member:
                                                for chunk in iter(lambda: member.read(1024 * 1024), b""):
                                                    size += len(chunk)
                                                    for digest in digests.values():
                                                        digest.update(chunk)
                                            actual_hashes = {name: digest.hexdigest() for name, digest in digests.items()}
                                            if size != record["size_bytes"] or actual_hashes != record["hashes"]:
                                                bundle_issues.append({"location": archive_name, "expected": record["hashes"], "actual": actual_hashes, "message": "Bundled evidence bytes do not match the five-hash inventory."})
                                        except KeyError:
                                            bundle_issues.append({"location": archive_name, "actual": "missing", "message": "Evidence file is missing from the ZIP."})
                            for extra_name in sorted(bundle_names - expected_entries):
                                bundle_issues.append({"location": extra_name, "message": "Unexpected unlisted entry is present in the ZIP."})
                except Exception as exc:
                    bundle_issues.append({"location": bundle_path, "message": f"Bundle could not be validated: {exc}"})
                add_step("bundle", "Downloadable case bundle and evidence payload", "failed" if bundle_issues else "passed",
                         f"Validated the signed manifest and contents of {os.path.basename(bundle_path)}." if not bundle_issues else f"Found {len(bundle_issues)} bundle problem(s).",
                         bundle_path, bundle_issues)

            # Optional source re-hash gives path-level mismatch diagnostics.
            if check_evidence and case_info.source_path:
                from core.ingest import get_vfs
                from core.integrity import hash_file
                conn = sqlite3.connect(case_info.db_path)
                baseline = {r[0]: r[1] for r in conn.execute("SELECT path,sha256 FROM baseline_files")}
                conn.close()
                source_issues = []
                try:
                    vfs = get_vfs(case_info.source_path)
                    current_paths = set()
                    for root, dirs, files in vfs.walk(""):
                        for filename in files:
                            rel = f"{root}/{filename}" if root else filename
                            current_paths.add(rel)
                            if rel in baseline:
                                try:
                                    with vfs.open(rel) as stream:
                                        actual = hash_file(stream)
                                    if actual != baseline[rel]:
                                        source_issues.append({"location": rel, "expected": baseline[rel], "actual": actual, "message": "Evidence file changed since baseline."})
                                except Exception as exc:
                                    source_issues.append({"location": rel, "message": f"Evidence could not be read: {exc}"})
                    for rel in sorted(set(baseline) - current_paths):
                        source_issues.append({"location": rel, "expected": baseline[rel], "actual": "missing", "message": "Evidence file is missing."})
                    for rel in sorted(current_paths - set(baseline)):
                        source_issues.append({"location": rel, "actual": "new file", "message": "Evidence file was added after baseline."})
                except Exception as exc:
                    source_issues.append({"location": case_info.source_path, "message": f"Evidence source could not be checked: {exc}"})
                add_step("evidence", "Evidence source vs. sealed baseline", "failed" if source_issues else "passed",
                         f"Re-hashed {len(baseline)} baseline files; found {len(source_issues)} issue(s)." if source_issues else f"All {len(baseline)} files match and no additions were found.",
                         case_info.source_path, source_issues)
            elif check_evidence:
                add_step("evidence", "Evidence source vs. sealed baseline", "warning", "No source path is recorded; original evidence cannot be re-hashed.", "case_metadata.source_path")

            # Token presence is only informational until RFC 3161 parsing and trust validation are implemented.
            tsa_path = os.path.join(case_info.case_dir, "seal_tsa.tsr")
            add_step("timestamp", "RFC 3161 timestamp token", "warning",
                     (f"Token present ({os.path.getsize(tsa_path)} bytes), but status, imprint, nonce, and TSA certificate chain are not validated." if os.path.exists(tsa_path)
                      else "No timestamp token is present."), tsa_path)

            failed = sum(s["status"] == "failed" for s in steps)
            warnings = sum(s["status"] == "warning" for s in steps)
            trusted = any(s["id"] == "identity" and s["status"] == "passed" for s in steps)
            overall = "failed" if failed else ("verified" if warnings == 0 and trusted else "internally_consistent")
            return {"success": True, "overall": overall, "trusted_signer": trusted,
                    "summary": {"passed": sum(s["status"] == "passed" for s in steps), "warnings": warnings,
                                "failed": failed, "checks": len(steps)}, "steps": steps}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # ── Task tracking for SSE ────────────────────────────────────

    def start_task(self, case_id: str, operation: str, func, *args) -> str:
        """Run an operation in a background thread, streaming messages via queue."""
        import queue
        task_id = f"{case_id}_{operation}_{uuid.uuid4().hex[:12]}"
        msg_queue = queue.Queue()

        def progress_cb(msg):
            msg_queue.put({"type": "progress", "message": msg})

        def wrapper():
            try:
                result = func(*args, progress_cb=progress_cb)
                msg_queue.put({"type": "complete", "result": result})
            except Exception as e:
                msg_queue.put({"type": "error", "message": str(e)})

        thread = threading.Thread(target=wrapper, daemon=True)

        with self._lock:
            self._running_tasks[task_id] = {
                "thread": thread,
                "queue": msg_queue,
                "operation": operation,
                "case_id": case_id,
                "started": time.time(),
            }

        thread.start()
        return task_id

    def get_task_messages(self, task_id: str):
        """Generator yielding SSE messages for a running task."""
        import queue
        with self._lock:
            task = self._running_tasks.get(task_id)
        if not task:
            yield {"type": "error", "message": "Task not found"}
            return

        msg_queue = task["queue"]
        while True:
            try:
                msg = msg_queue.get(timeout=30)
                yield msg
                if msg["type"] in ("complete", "error"):
                    with self._lock:
                        self._running_tasks.pop(task_id, None)
                    return
            except queue.Empty:
                yield {"type": "heartbeat", "message": "..."}
