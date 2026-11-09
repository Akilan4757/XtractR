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

    def create_bundle(self, include_evidence: bool = True, progress_cb=None):
        case_id = self.db.get_metadata("case_id")
        timestamp_str = str(TimeProvider.now_ms())
        bundle_name = f"{case_id}_xtractr_bundle_{timestamp_str}.zip"
        bundle_path = os.path.join(self.export_dir, bundle_name)

        logger.info(f"Creating Sealed Export Bundle: {bundle_path}")

        try:
            # â”€â”€ STEP 1: TOCTOU guard & DB checkpoint â€” before any hashing â”€â”€â”€â”€â”€â”€â”€â”€â”€
            # Flush WAL pages to disk
            self.db.checkpoint()

            try:
                evidence_report = self._build_evidence_hash_report(progress_cb, include_evidence)
            except Exception as error:
                logger.critical(f"TOCTOU_TAMPER_DETECTED: {error}")
                self.db.log_event("TOCTOU_TAMPER_DETECTED", str(error), actor="SYSTEM")
                raise SystemExit(10) from error
            self.db.log_event("TOCTOU_VERIFIED", f"All {len(evidence_report['files'])} evidence files matched their baseline", actor="SYSTEM")
            if progress_cb:
                progress_cb(f"Evidence verified and inventoried: {len(evidence_report['files'])} files, 5 hashes each")

            # Write SEAL_INIT log event to DB before snapshotting
            self.db.log_event("SEAL_INIT", f"Initializing cryptographic seal for case {case_id}", actor="SYSTEM")

            # â”€â”€ STEP 2: Snapshot DB state for Merkle computations â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            # All log writes are done. Now snapshot the DB with a read-only cursor.
            cursor = self.db._conn.cursor()

            # Evidence root
            cursor.execute("SELECT path, size, mtime, sha256 FROM baseline_files ORDER BY path ASC")
            evidence_hashes = [hashlib.sha256(canonical_json({"path": row[0], "size": row[1], "mtime": row[2], "sha256": row[3]})).hexdigest() for row in cursor.fetchall()]
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

            # Log Merkle root
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

            execution_id = self.db.get_metadata("session_execution_id") or "UNKNOWN"

            # â”€â”€ STEP 4: Build and sign the seal â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            signed_payload = {
                "format_version": 2,
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
            # RFC 3161 request bound to canonical signed seal bytes.
            tsa_token_path = os.path.join(self.case_dir, "seal_tsa.tsr")
            try:
                tsa_token = TSAClient().request_timestamp(canonical_json(seal_data))
                if tsa_token:
                    TSAClient.save_token(tsa_token, tsa_token_path)
                else:
                    logger.warning("External TSA timestamp unavailable")
            except Exception as e:
                logger.warning(f"TSA anchoring failed (non-fatal): {e}")

            # â”€â”€ STEP 5: Sign individual files â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            self._sign_file("seal.json")
            self._sign_file("case.db")
            self._sign_file("report.html")

            corr_basename = "correlation.json"
            corr_path = os.path.join(self.case_dir, corr_basename)
            if os.path.exists(corr_path):
                self._sign_file(corr_basename)

            ledger_basename = os.path.basename(self.db.get_ledger_path())
            ledger_src = self.db.get_ledger_path()
            ledger_dst = os.path.join(self.case_dir, ledger_basename)
            if os.path.exists(ledger_src) and ledger_src != ledger_dst:
                shutil.copy(ledger_src, ledger_dst)
            self._sign_file(ledger_basename)

            # â”€â”€ STEP 6: Build manifest and ZIP â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            files_to_pack = [
                "case.db", "case.db.sig",
                "seal.json", "seal.json.sig",
                "report.html", "report.html.sig",
                "timeline.json", "timeline.csv",
                "evidence_manifest.json", "README_EVIDENCE.md",
                ledger_basename, ledger_basename + ".sig",
            ]

            if os.path.exists(corr_path):
                files_to_pack.extend([corr_basename, corr_basename + ".sig"])

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
                "evidence_payload_included": bool(include_evidence),
                "evidence_file_count": len(evidence_manifest["files"]),
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
                if include_evidence:
                    self._write_evidence_payload(zf, evidence_manifest, progress_cb)

            logger.info(f"Bundle created: {bundle_path} ({len(log_hashes)} log events sealed)")
            return bundle_path

        except Exception as e:
            logger.error(f"Sealed export failed. Rolling back partially created export artifacts: {e}")
            if os.path.exists(bundle_path):
                try:
                    os.unlink(bundle_path)
                except Exception:
                    pass
            cleanup_names = [
                "seal.json", "seal.json.sig",
                "case.db.sig", "report.html.sig",
                "correlation.json.sig", "investigator.pub",
                "investigator.crt", "seal_tsa.tsr",
                "manifest.json", "manifest.json.sig"
            ]
            ledger_basename = os.path.basename(self.db.get_ledger_path())
            cleanup_names.extend([ledger_basename + ".sig"])
            
            for fname in cleanup_names:
                fpath = os.path.join(self.case_dir, fname)
                if os.path.exists(fpath):
                    try:
                        os.unlink(fpath)
                    except Exception:
                        pass
            raise e

    def _build_evidence_hash_report(self, progress_cb=None, include_evidence=True):
        """Create a portable, multi-algorithm hash inventory of source files."""
        from .ingest import get_vfs

        source_path = self.db.get_metadata("source_path")
        if not source_path:
            raise RuntimeError("Cannot create evidence hash report without a recorded source path")
        vfs = get_vfs(source_path)
        cursor = self.db._conn.cursor()
        cursor.execute("SELECT path, size, mtime, sha256 FROM baseline_files ORDER BY path ASC")
        baseline = {row[0]: {"size": row[1], "mtime": row[2], "sha256": row[3]} for row in cursor.fetchall()}
        paths = set()
        for root, dirs, files in vfs.walk(""):
            for name in files:
                paths.add(f"{root}/{name}" if root else name)
        if paths != set(baseline):
            added = sorted(paths - baseline.keys())
            missing = sorted(baseline.keys() - paths)
            raise RuntimeError(f"Evidence inventory changed while preparing export (new={added[:10]}, missing={missing[:10]})")

        algorithms = ("sha256", "sha512", "sha384", "sha1", "md5")
        records = []
        total_bytes = sum((baseline[path]["size"] or 0) for path in paths)
        completed_bytes = 0
        progress_every = max(1, len(paths) // 100)
        for index, path in enumerate(sorted(paths), 1):
            digests = {name: hashlib.new(name, usedforsecurity=name not in ("md5", "sha1")) for name in algorithms}
            size = 0
            last_progress_bytes = 0
            with vfs.open(path, "rb") as stream:
                while True:
                    chunk = stream.read(1024 * 1024)
                    if not chunk:
                        break
                    size += len(chunk)
                    for digest in digests.values():
                        digest.update(chunk)
                    if progress_cb and size - last_progress_bytes >= 256 * 1024 * 1024:
                        progress_cb(f"Hashing evidence inventory: {index}/{len(paths)} files, {completed_bytes + size}/{total_bytes} bytes")
                        last_progress_bytes = size
            calculated = {name: digest.hexdigest() for name, digest in digests.items()}
            expected = baseline[path]
            if size != expected["size"] or calculated["sha256"] != expected["sha256"]:
                raise RuntimeError(f"Evidence changed while hashing export inventory: {path}")
            completed_bytes += size
            if progress_cb and (index == 1 or index == len(paths) or index % progress_every == 0):
                progress_cb(f"Hashing evidence inventory: {index}/{len(paths)} files, {completed_bytes}/{total_bytes} bytes")
            records.append({
                "path": path,
                "size_bytes": size,
                "mtime_utc_epoch_seconds": expected["mtime"],
                "hashes": calculated,
            })

        report = {
            "format_version": 1,
            "case_id": self.db.get_metadata("case_id"),
            "source": os.path.basename(os.path.abspath(source_path)),
            "generated_at_epoch_ms": TimeProvider.now_ms(),
            "evidence_payload_included": bool(include_evidence),
            "hash_algorithms": list(algorithms),
            "files": records,
        }
        readme = [
            f"# Evidence hash inventory — {report['case_id']}", "",
            f"Generated (Unix epoch milliseconds): {report['generated_at_epoch_ms']}",
            f"Evidence source: `{report['source']}`", f"Files inventoried: {len(records)}", "",
            "## Hash algorithms", "",
            "SHA-256, SHA-512, and SHA-384 are included for strong verification. SHA-1 and MD5 are included for legacy tool and evidence compatibility; do not use them alone to establish integrity.",
            "", ("Evidence files are included under the `evidence/` directory in the case bundle. The source media should still be preserved separately as the original acquisition." if include_evidence else "Evidence file bytes are not included in this bundle. Use the SHA-256 inventory to compare against the original evidence source, which must be preserved separately."),
            "", "## File inventory", "",
            "| Evidence path | Size (bytes) | SHA-256 | SHA-512 | SHA-384 | SHA-1 | MD5 |",
            "|---|---:|---|---|---|---|---|",
        ]
        for record in records:
            safe_path = record["path"].replace("|", "\\|").replace("`", "\\`")
            hashes = record["hashes"]
            readme.append(f"| `{safe_path}` | {record['size_bytes']} | {hashes['sha256']} | {hashes['sha512']} | {hashes['sha384']} | {hashes['sha1']} | {hashes['md5']} |")
        with open(os.path.join(self.case_dir, "evidence_manifest.json"), "wb") as stream:
            stream.write(canonical_json(report))
        with open(os.path.join(self.case_dir, "README_EVIDENCE.md"), "w", encoding="utf-8", newline="\n") as stream:
            stream.write("\n".join(readme) + "\n")
        return report

    def _write_evidence_payload(self, archive: zipfile.ZipFile, report: dict, progress_cb=None):
        """Stream original VFS files into the bundle and verify every hash again."""
        from pathlib import PurePosixPath
        from .ingest import get_vfs

        vfs = get_vfs(self.db.get_metadata("source_path"))
        algorithms = tuple(report["hash_algorithms"])
        seen_archive_names = set()
        total_bytes = sum(record["size_bytes"] for record in report["files"])
        completed_bytes = 0
        progress_every = max(1, len(report["files"]) // 100)
        for index, record in enumerate(report["files"], 1):
            virtual_path = record["path"].replace("\\", "/")
            path = PurePosixPath(virtual_path)
            if path.is_absolute() or not path.parts or any(part in ("", ".", "..") for part in path.parts) or ":" in path.parts[0]:
                raise RuntimeError(f"Unsafe evidence path cannot be packaged: {record['path']!r}")
            archive_name = "evidence/" + path.as_posix()
            if archive_name in seen_archive_names:
                raise RuntimeError(f"Duplicate normalized evidence path: {record['path']!r}")
            seen_archive_names.add(archive_name)
            digests = {name: hashlib.new(name, usedforsecurity=name not in ("md5", "sha1")) for name in algorithms}
            size = 0
            last_progress_bytes = 0
            with vfs.open(record["path"], "rb") as source, archive.open(archive_name, "w", force_zip64=True) as target:
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    size += len(chunk)
                    for digest in digests.values():
                        digest.update(chunk)
                    target.write(chunk)
                    if progress_cb and size - last_progress_bytes >= 256 * 1024 * 1024:
                        progress_cb(f"Packaging evidence payload: {index}/{len(report['files'])} files, {completed_bytes + size}/{total_bytes} bytes")
                        last_progress_bytes = size
            actual_hashes = {name: digest.hexdigest() for name, digest in digests.items()}
            if size != record["size_bytes"] or actual_hashes != record["hashes"]:
                raise RuntimeError(f"Evidence changed while being packaged: {record['path']}")
            completed_bytes += size
            if progress_cb and (index == 1 or index == len(report["files"]) or index % progress_every == 0):
                progress_cb(f"Packaging evidence payload: {index}/{len(report['files'])} files, {completed_bytes}/{total_bytes} bytes")

    def _sign_file(self, filename):
        path = os.path.join(self.case_dir, filename)
        if not os.path.exists(path):
            return

        with open(path, "rb") as f:
            data = f.read()

        sig = self.identity.sign_data(data)

        with open(path + ".sig", "w") as f:
            f.write(sig.hex())
