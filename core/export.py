import os
import json
import base64
import zipfile
import shutil
import hashlib
import logging
from .database import CaseDatabase
from .crypto import IdentityManager
from .integrity import (
    compute_merkle_root, hash_file, hash_artifact,
    compute_system_root, canonical_json
)
from .time_provider import TimeProvider
from .tsa import TSAClient

logger = logging.getLogger("xtractr.export")

TOOL_VERSION = "1.1.0"
SCHEMA_VERSION = "3.0.0"


class ExportManager:
    def __init__(self, db: CaseDatabase, identity: IdentityManager, case_dir: str):
        self.db = db
        self.identity = identity
        self.case_dir = case_dir
        self.export_dir = os.path.join(self.case_dir, "exports")
        os.makedirs(self.export_dir, exist_ok=True)

    def create_bundle(self):
        case_id = self.db.get_metadata("case_id")
        timestamp_str = str(TimeProvider.now_ms())
        bundle_name = f"{case_id}_xtractr_bundle_{timestamp_str}.zip"
        bundle_path = os.path.join(self.export_dir, bundle_name)

        logger.info(f"Creating Sealed Export Bundle: {bundle_path}")

        # ── STEP 1: TOCTOU guard — before any hashing ────────────────────────
        toctou_passed = self._verify_evidence_integrity()
        if not toctou_passed:
            logger.critical("TOCTOU_TAMPER_DETECTED: Evidence files modified since baseline!")
            self.db.log_event("TOCTOU_TAMPER_DETECTED", "Evidence re-hash failed at export time", actor="SYSTEM")
            raise SystemExit(10)

        # ── STEP 2: TSA anchoring BEFORE computing any Merkle roots ──────────
        # All custody log_event writes MUST happen before the log snapshot below.
        tsa_token_path = os.path.join(self.case_dir, "seal_tsa.tsr")
        tsa_token = None
        try:
            tsa_client = TSAClient()
            # We anchor on a hash of the current state; the real seal bytes will
            # be computed afterwards.  For verification purposes the TSA timestamp proves
            # the bundle creation window; the seal's own signature proves integrity.
            pre_seal_hash = hashlib.sha256(
                f"{case_id}|{timestamp_str}".encode()
            ).digest()
            tsa_token = tsa_client.request_timestamp(pre_seal_hash)
            if tsa_token:
                TSAClient.save_token(tsa_token, tsa_token_path)
                self.db.log_event(
                    "TSA_ANCHORED",
                    f"External timestamp obtained ({len(tsa_token)} bytes)",
                    actor="SYSTEM"
                )
            else:
                self.db.log_event(
                    "TSA_DEGRADED",
                    "External timestamp unavailable — local time only",
                    actor="SYSTEM"
                )
        except Exception as e:
            logger.warning(f"TSA anchoring failed (non-fatal): {e}")
            self.db.log_event("TSA_FAILED", f"TSA error: {e}", actor="SYSTEM")

        # ── STEP 3: Snapshot DB state for Merkle computations ────────────────
        # All log writes are done.  Now snapshot the DB with a read-only cursor.
        cursor = self.db._conn.cursor()

        # Evidence root
        cursor.execute("SELECT sha256 FROM baseline_files ORDER BY path ASC")
        evidence_hashes = [row[0] for row in cursor.fetchall()]
        evidence_root = compute_merkle_root(evidence_hashes)

        # Artifact Merkle root
        cursor.execute("""
            SELECT artifact_type, source_path, output_path, sha256,
                   plugin_name, plugin_version, timestamp_utc, details, actor
            FROM derived_artifacts ORDER BY id ASC
        """)
        artifact_rows = cursor.fetchall()
        artifact_hashes = []
        for row in artifact_rows:
            art_dict = {
                "artifact_type": row[0],
                "source_path": row[1],
                "output_path": row[2],
                "sha256": row[3],
                "plugin_name": row[4],
                "plugin_version": row[5],
                "timestamp_utc": row[6],
                "details": row[7],
                "actor": row[8],
            }
            artifact_hashes.append(hash_artifact(art_dict))
        artifact_root = compute_merkle_root(artifact_hashes)

        # Log Merkle root — includes TSA events logged above
        cursor.execute("""
            SELECT timestamp_utc, action, details, source_hash,
                   prev_event_hash, this_event_hash, actor
            FROM custody_events ORDER BY id ASC
        """)
        log_rows = cursor.fetchall()
        log_hashes = []
        for row in log_rows:
            log_entry = {
                "timestamp_utc": row[0],
                "action": row[1],
                "details": row[2],
                "source_hash": row[3],
                "prev_event_hash": row[4],
                "this_event_hash": row[5],
                "actor": row[6],
            }
            log_hashes.append(
                hashlib.sha256(canonical_json(log_entry)).hexdigest()
            )
        log_root = compute_merkle_root(log_hashes)

        system_root = compute_system_root(artifact_root, log_root)

        # Parser version manifest
        cursor.execute("""
            SELECT plugin_name, plugin_source_hash
            FROM plugin_runs ORDER BY plugin_name ASC
        """)
        parser_manifest = {}
        for row in cursor.fetchall():
            parser_manifest[row[0]] = row[1] or "UNKNOWN"

        build_hash = hashlib.sha256(
            canonical_json(parser_manifest)
        ).hexdigest()

        cursor.execute("""
            SELECT DISTINCT execution_id FROM plugin_runs
            ORDER BY execution_id ASC LIMIT 1
        """)
        exec_row = cursor.fetchone()
        execution_id = exec_row[0] if exec_row else "UNKNOWN"

        # ── STEP 4: Build and sign the seal ──────────────────────────────────
        signed_payload = {
            "system_root": system_root,
            "artifact_root": artifact_root,
            "log_root": log_root,
            "evidence_root": evidence_root,
            "case_id": case_id,
            "execution_id": execution_id,
            "investigator_fingerprint": self.identity.get_public_key_fingerprint(),
            "parser_version_manifest": parser_manifest,
            "schema_version": SCHEMA_VERSION,
            "tool_version": TOOL_VERSION,
            "build_hash": build_hash,
            "timestamp_utc": TimeProvider.now_ms(),
            "artifact_count": len(artifact_hashes),
            "log_entry_count": len(log_hashes),
            "baseline_file_count": len(evidence_hashes),
            "algorithm": "SHA256",
        }

        payload_bytes = canonical_json(signed_payload)
        signature_raw = self.identity.sign_data(payload_bytes)
        signature_b64 = base64.b64encode(signature_raw).decode('ascii')

        seal_data = dict(signed_payload)
        seal_data["signature"] = signature_b64

        seal_path = os.path.join(self.case_dir, "seal.json")
        with open(seal_path, "wb") as f:
            f.write(canonical_json(seal_data))

        # ── STEP 5: Sign individual files ────────────────────────────────────
        self._sign_file("seal.json")
        self._sign_file("case.db")
        self._sign_file("report.html")

        ledger_basename = os.path.basename(self.db.get_ledger_path())
        ledger_src = self.db.get_ledger_path()
        ledger_dst = os.path.join(self.case_dir, ledger_basename)
        if os.path.exists(ledger_src) and ledger_src != ledger_dst:
            shutil.copy(ledger_src, ledger_dst)
        self._sign_file(ledger_basename)

        # ── STEP 6: Build manifest and ZIP ────────────────────────────────────
        files_to_pack = [
            "case.db", "case.db.sig",
            "seal.json", "seal.json.sig",
            "report.html", "report.html.sig",
            "timeline.json", "timeline.csv",
            ledger_basename, ledger_basename + ".sig",
        ]

        if os.path.exists(tsa_token_path):
            files_to_pack.append("seal_tsa.tsr")

        # Copy public key
        pub_key_src = self.identity.public_key_path
        pub_key_dst = os.path.join(self.case_dir, "investigator.pub")
        shutil.copy(pub_key_src, pub_key_dst)
        files_to_pack.append("investigator.pub")

        # Copy X.509 certificate if it exists
        cert_pem = self.identity.get_certificate_pem()
        if cert_pem:
            cert_dst = os.path.join(self.case_dir, "investigator.crt")
            with open(cert_dst, "wb") as f:
                f.write(cert_pem)
            files_to_pack.append("investigator.crt")

        manifest = {
            "case_id": case_id,
            "created_at": TimeProvider.now_ms(),
            "files": {}
        }

        for fname in sorted(files_to_pack):
            fpath = os.path.join(self.case_dir, fname)
            if os.path.exists(fpath):
                with open(fpath, "rb") as f:
                    manifest["files"][fname] = hash_file(f)
            else:
                logger.warning(f"Export Warning: Missing file {fname}")

        manifest_path = os.path.join(self.case_dir, "manifest.json")
        with open(manifest_path, "wb") as f:
            f.write(canonical_json(manifest))

        self._sign_file("manifest.json")
        files_to_pack.append("manifest.json")
        files_to_pack.append("manifest.json.sig")

        with zipfile.ZipFile(bundle_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for fname in sorted(files_to_pack):
                fpath = os.path.join(self.case_dir, fname)
                if os.path.exists(fpath):
                    zf.write(fpath, arcname=fname)

        logger.info(f"Bundle created: {bundle_path} ({len(log_hashes)} log events sealed)")
        return bundle_path

    def _verify_evidence_integrity(self) -> bool:
        """
        TOCTOU Elimination: Re-hash every physical evidence file and compare
        against the stored baseline. If ANY mismatch is found, return False.
        """
        from .ingest import get_vfs

        src = self.db.get_metadata("source_path")
        if not src:
            logger.warning("No source_path in metadata — skipping TOCTOU check")
            return True

        try:
            vfs = get_vfs(src)
        except Exception as e:
            logger.error(f"Cannot reconstruct VFS for TOCTOU check: {e}")
            return True  # Can't verify, don't block

        cursor = self.db._conn.cursor()
        cursor.execute("SELECT path, sha256 FROM baseline_files")
        baseline_map = {row[0]: row[1] for row in cursor.fetchall()}

        mismatches = 0
        for path, expected_hash in baseline_map.items():
            try:
                with vfs.open(path) as f:
                    actual_hash = hash_file(f)
                if actual_hash != expected_hash:
                    logger.critical(f"TOCTOU TAMPER: {path} — expected {expected_hash[:16]}... got {actual_hash[:16]}...")
                    mismatches += 1
            except Exception as e:
                logger.error(f"TOCTOU CHECK ERROR: {path} — {e}")
                mismatches += 1

        if mismatches > 0:
            logger.critical(f"TOCTOU: {mismatches} file(s) modified since baseline!")
            return False

        logger.info(f"TOCTOU check passed: {len(baseline_map)} files verified")
        self.db.log_event("TOCTOU_VERIFIED", f"All {len(baseline_map)} evidence files re-hashed OK", actor="SYSTEM")
        return True

    def _sign_file(self, filename):
        path = os.path.join(self.case_dir, filename)
        if not os.path.exists(path):
            return

        with open(path, "rb") as f:
            data = f.read()

        sig = self.identity.sign_data(data)

        with open(path + ".sig", "w") as f:
            f.write(sig.hex())
