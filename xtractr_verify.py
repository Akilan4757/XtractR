"""
XtractR Independent Verifier â€” Cryptographic Seal Verification

Supports two modes:
  1. xtractr_verify.py verify <case_dir> --pub-key <path>
  2. xtractr_verify.py --case-dir <dir> --pub-key <path>  (legacy)
  3. xtractr_verify.py verify-bundle <received.zip> --expect-fingerprint <sha256>

Verification steps:
  1. SQLite integrity check (PRAGMA integrity_check)
  2. Recompute all artifact hashes from DB
  3. Rebuild artifact Merkle tree
  4. Recompute all custody log entry hashes
  5. Rebuild log Merkle tree
  6. Recompute system_root = SHA256(artifact_root || log_root)
  7. Verify evidence_root from baseline_files
  8. Cross-check count fields (artifact_count, log_entry_count, baseline_file_count)
  9. Verify investigator_fingerprint matches public key
  10. Validate build_hash from parser_version_manifest
  11. Reconstruct signed payload from seal.json fields
  12. Verify Ed25519 signature
  13. Validate schema_version and algorithm
  14. Cross-validate JSONL ledger against SQLite (if present)
  15. Verify X.509 certificate (if provided via --cert)
  16. Check TSA token presence

Exit codes:
  0  = VERIFIED
  1  = GENERAL_FAILURE
  10 = MERKLE_MISMATCH
  11 = SIGNATURE_INVALID
  12 = SCHEMA_MISMATCH
  13 = VERSION_DRIFT
  14 = JSONL_MISMATCH
"""
import sys
import os
import sqlite3
import hashlib
import json
import base64
import argparse
import datetime
import re
import stat
import tempfile
import zipfile
from collections import Counter
from typing import List, Dict, Optional

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.exceptions import InvalidSignature
except ImportError:
    print("Error: 'cryptography' library required for verification.")
    sys.exit(1)

EXIT_OK = 0
EXIT_GENERAL = 1
EXIT_MERKLE_MISMATCH = 10
EXIT_SIGNATURE_INVALID = 11
EXIT_SCHEMA_MISMATCH = 12
EXIT_VERSION_DRIFT = 13
EXIT_JSONL_MISMATCH = 14

COLORS = {
    "GREEN": "\033[92m",
    "RED": "\033[91m",
    "YELLOW": "\033[93m",
    "RESET": "\033[0m",
    "INFO": ""
}


def print_result(msg, status="INFO"):
    print(f"{COLORS.get(status, '')}[{status}] {msg}{COLORS['RESET']}")


def canonical_json(obj) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(',', ':'),
        ensure_ascii=True, default=str
    ).encode('utf-8')


def compute_merkle_root(hashes: List[str]) -> str:
    if not hashes:
        return hashlib.sha256(b"EMPTY").hexdigest()

    def raw(value):
        try:
            result = bytes.fromhex(value)
            return result if len(result) == 32 else value.encode('utf-8')
        except (ValueError, TypeError):
            return str(value).encode('utf-8')
    leaves = [hashlib.sha256(b"\x00" + raw(h)).digest() for h in hashes]
    current_level = leaves

    while len(current_level) > 1:
        next_level = []
        for i in range(0, len(current_level), 2):
            if i + 1 < len(current_level):
                left = current_level[i]
                right = current_level[i + 1]
                combined = hashlib.sha256(b"\x01" + left + right).digest()
            else:
                # Pass up the odd node directly without duplicate padding or re-hashing
                combined = current_level[i]
            next_level.append(combined)
        current_level = next_level

    return current_level[0].hex()


def compute_system_root(artifact_root: str, log_root: str) -> str:
    return hashlib.sha256(
        (artifact_root + log_root).encode('utf-8')
    ).hexdigest()


def hash_artifact(artifact_dict: dict) -> str:
    return hashlib.sha256(canonical_json(artifact_dict)).hexdigest()


def compute_hash(filepath) -> Optional[str]:
    sha = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(65536):
                sha.update(chunk)
        return sha.hexdigest()
    except Exception as e:
        print_result(f"Failed to hash file {filepath}: {e}", "RED")
        return None


def compute_public_key_fingerprint(pub_key_path: str) -> Optional[str]:
    """Compute SHA-256 fingerprint of public key DER bytes (matches crypto.py)."""
    try:
        with open(pub_key_path, "rb") as f:
            pub_key = serialization.load_pem_public_key(f.read())
        der = pub_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return hashlib.sha256(der).hexdigest()
    except Exception as e:
        print_result(f"Failed to compute public key fingerprint: {e}", "RED")
        return None


def verify_ed25519_signature(pub_key_path, data, signature_encoded, encoding="auto"):
    """
    Unified Ed25519 signature verification (Fix #2).
    
    Args:
        pub_key_path: Path to PEM public key file
        data: The signed data (bytes)
        signature_encoded: The signature string (hex or base64)
        encoding: 'hex', 'base64', or 'auto' (detect from content)
    
    Returns True if signature is valid, False otherwise.
    """
    try:
        with open(pub_key_path, "rb") as f:
            pub_key = serialization.load_pem_public_key(f.read())

        # Auto-detect encoding (Fix #2 â€” eliminate fragile dual-function API)
        if encoding == "auto":
            # Base64 strings contain +, /, = characters that hex strings don't
            # Hex strings are strictly [0-9a-fA-F]
            try:
                bytes.fromhex(signature_encoded)
                # Ed25519 signatures are 64 bytes = 128 hex chars
                if len(signature_encoded) == 128:
                    encoding = "hex"
                else:
                    encoding = "base64"
            except ValueError:
                encoding = "base64"

        if encoding == "hex":
            signature = bytes.fromhex(signature_encoded)
        elif encoding == "base64":
            signature = base64.b64decode(signature_encoded)
        else:
            print_result(f"Unknown signature encoding: {encoding}", "RED")
            return False

        pub_key.verify(signature, data)
        return True
    except InvalidSignature:
        print_result(f"Signature cryptographically INVALID (encoding={encoding})", "RED")
        return False
    except Exception as e:
        print_result(f"Signature verification error (encoding={encoding}): {e}", "RED")
        return False


# Backwards-compatible aliases for clarity in call sites
def verify_signature(pub_key_path, data, signature_hex):
    """Verify hex-encoded Ed25519 signature (used for .sig files)."""
    return verify_ed25519_signature(pub_key_path, data, signature_hex, encoding="hex")


def verify_ed25519_b64(pub_key_path, payload_bytes, signature_b64):
    """Verify base64-encoded Ed25519 signature (used for seal.json)."""
    return verify_ed25519_signature(pub_key_path, payload_bytes, signature_b64, encoding="base64")


def load_public_key_from_cert(cert_path, strict=False):
    """Extract public key from X.509 certificate and save as temp pub key."""
    try:
        from cryptography import x509
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())

        # Validate certificate dates
        now = datetime.datetime.now(datetime.UTC)
        if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
            if strict:
                print_result("Certificate EXPIRED or NOT YET VALID â€” STRICT mode: REJECTING", "RED")
                return None
            else:
                print_result("Certificate EXPIRED or NOT YET VALID (use --strict to reject)", "YELLOW")

        # Extract subject info
        subject = cert.subject
        cn = subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        org = subject.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)
        print_result(f"Certificate Subject: CN={cn[0].value if cn else 'N/A'}, O={org[0].value if org else 'N/A'}", "INFO")

        # Write public key to temp file for verification functions
        import tempfile
        pub_key = cert.public_key()
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".pub")
        tmp.write(pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        tmp.close()
        return tmp.name
    except Exception as e:
        print_result(f"Certificate loading failed: {e}", "RED")
        return None


def check_sqlite_integrity(db_path):
    """Run PRAGMA integrity_check on the SQLite database."""
    try:
        conn = sqlite3.connect(db_path)
        conn.execute("PRAGMA query_only = ON")
        cursor = conn.cursor()
        cursor.execute("PRAGMA integrity_check")
        result = cursor.fetchone()
        conn.close()
        if result and result[0] == "ok":
            print_result("SQLite Integrity: OK", "GREEN")
            return True
        else:
            print_result(f"SQLite Integrity FAILED: {result}", "RED")
            return False
    except Exception as e:
        print_result(f"SQLite integrity check error: {e}", "RED")
        return False


def verify_jsonl_ledger(case_dir, db_path):
    """
    Cross-validate the JSONL append-only ledger against the SQLite custody_events.
    Compares ALL fields, not just hashes.
    Returns (success, mismatch_count).
    """
    # Find the JSONL file
    jsonl_path = None
    try:
        for fname in os.listdir(case_dir):
            if fname.endswith("_custody_ledger.jsonl") or fname == "case_custody_ledger.jsonl":
                jsonl_path = os.path.join(case_dir, fname)
                break
    except Exception as e:
        print_result(f"Error scanning for JSONL ledger: {e}", "RED")
        return False, 1

    if not jsonl_path or not os.path.exists(jsonl_path):
        print_result("JSONL ledger not found â€” skipping cross-validation (legacy bundle)", "YELLOW")
        return True, 0

    print_result("Cross-validating JSONL ledger against SQLite...", "INFO")

    # Load JSONL entries
    jsonl_entries = []
    with open(jsonl_path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if line:
                try:
                    jsonl_entries.append(json.loads(line))
                except json.JSONDecodeError as e:
                    print_result(f"JSONL parse error at line {line_num}: {e}", "RED")

    # Load SQLite entries
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA query_only = ON")
    cursor = conn.cursor()
    cursor.execute("""
        SELECT timestamp_utc, action, details, source_hash,
               prev_event_hash, this_event_hash, actor
        FROM custody_events ORDER BY id ASC
    """)
    db_rows = cursor.fetchall()
    conn.close()

    mismatches = 0
    FIELDS = ["timestamp_utc", "action", "details", "source_hash",
              "prev_event_hash", "this_event_hash", "actor"]

    if len(jsonl_entries) != len(db_rows):
        print_result(f"JSONL/SQLite entry count mismatch: JSONL={len(jsonl_entries)} SQLite={len(db_rows)}", "RED")
        mismatches += 1

    # Compare each entry â€” ALL fields, not just hash
    for i, db_row in enumerate(db_rows):
        if i >= len(jsonl_entries):
            print_result(f"Missing JSONL entry at index {i}", "RED")
            mismatches += 1
            continue

        jsonl_entry = jsonl_entries[i]
        db_entry = {
            "timestamp_utc": db_row[0],
            "action": db_row[1],
            "details": db_row[2],
            "source_hash": db_row[3],
            "prev_event_hash": db_row[4],
            "this_event_hash": db_row[5],
            "actor": db_row[6],
        }

        # Compare ALL fields
        for field in FIELDS:
            jsonl_val = jsonl_entry.get(field)
            db_val = db_entry[field]
            if str(jsonl_val) != str(db_val):
                print_result(
                    f"Field mismatch at entry {i}, field '{field}': "
                    f"JSONL={str(jsonl_val)[:32]} SQLite={str(db_val)[:32]}",
                    "RED"
                )
                mismatches += 1

    if mismatches == 0:
        print_result(f"JSONL Cross-Validation: VALID ({len(jsonl_entries)} entries, all fields checked)", "GREEN")
    else:
        print_result(f"JSONL Cross-Validation: FAILED ({mismatches} mismatches)", "RED")

    return mismatches == 0, mismatches


def verify_ledger(db_path):
    print_result("Verifying Ledger Integrity...", "INFO")
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA query_only = ON")

    cursor = conn.cursor()
    cursor.execute("SELECT * FROM custody_events ORDER BY id ASC")
    rows = cursor.fetchall()
    conn.close()

    expected_prev = "GENESIS_HASH_00000000000000000000000000000000"

    for row in rows:
        rid, ts, action, details, src_hash, prev_hash, this_hash, actor = row

        if prev_hash != expected_prev:
            print_result(f"Ledger Broken at ID {rid}: Link Mismatch", "RED")
            return False, None

        payload = f"{ts}|{action}|{details}|{src_hash}|{prev_hash}|{actor}".encode("utf-8")
        recalc = hashlib.sha256(payload).hexdigest()

        if recalc != this_hash:
            print_result(f"Ledger Tampered at ID {rid}: Hash Mismatch", "RED")
            return False, None

        expected_prev = this_hash

    print_result(f"Ledger Integrity: VALID ({len(rows)} events)", "GREEN")
    return True, expected_prev


def _normalize_seal_types(seal_dict: dict) -> dict:
    """
    Normalize types in a seal dictionary to prevent type coercion mismatches (Fix #3).
    
    When seal.json is written via canonical_json(default=str), integer fields stay as
    integers. But when read back via json.load(), Python may represent them differently
    (e.g., int vs float). This function forces consistent types to ensure
    canonical_json() always produces identical bytes.
    """
    INTEGER_FIELDS = {
        "timestamp_utc", "artifact_count", "log_entry_count",
        "baseline_file_count"
    }
    normalized = {}
    for k, v in seal_dict.items():
        if k in INTEGER_FIELDS and v is not None:
            try:
                normalized[k] = int(v)
            except (TypeError, ValueError):
                normalized[k] = v
        else:
            normalized[k] = v
    return normalized


def verify_merkle_seal(case_dir, pub_key_path):
    """
    Full cryptographic verification of the Merkle seal.
    Returns (success: bool, exit_code: int, failure_reason: str).
    """
    db_path = os.path.join(case_dir, "case.db")
    seal_path = os.path.join(case_dir, "seal.json")

    if not os.path.exists(seal_path):
        return False, EXIT_GENERAL, "seal.json not found"
    if not os.path.exists(db_path):
        return False, EXIT_GENERAL, "case.db not found"

    with open(seal_path, "r") as f:
        seal = _normalize_seal_types(json.load(f))

    if seal.get("format_version") != 2:
        return False, EXIT_SCHEMA_MISMATCH, "Unsupported or legacy bundle format; this verifier accepts format_version 2 only"

    # --- Validate schema_version ---
    schema_version = seal.get("schema_version", "")
    if not schema_version:
        return False, EXIT_SCHEMA_MISMATCH, "Missing schema_version in seal.json"
    print_result(f"Schema Version: {schema_version}", "INFO")

    # --- Validate algorithm field ---
    algorithm = seal.get("algorithm", "")
    if algorithm and algorithm != "SHA256":
        print_result(f"WARNING: Seal uses algorithm '{algorithm}', verifier only supports SHA256", "YELLOW")
    elif not algorithm:
        print_result("WARNING: No algorithm field in seal.json (assuming SHA256)", "YELLOW")

    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA query_only = ON")
    cursor = conn.cursor()

    # --- Step 1: Artifact Merkle Root ---
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
    computed_artifact_root = compute_merkle_root(artifact_hashes)

    # HARD FAIL if artifact_root is missing (Fix #4)
    seal_artifact_root = seal.get("artifact_root")
    if not seal_artifact_root:
        conn.close()
        return False, EXIT_MERKLE_MISMATCH, "MISSING artifact_root in seal.json â€” possible tampering"
    if computed_artifact_root != seal_artifact_root:
        conn.close()
        return False, EXIT_MERKLE_MISMATCH, (
            f"Artifact Merkle root mismatch: "
            f"computed={computed_artifact_root[:16]}... "
            f"seal={seal_artifact_root[:16]}..."
        )

    # --- Step 2: Log Merkle Root ---
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
    computed_log_root = compute_merkle_root(log_hashes)

    seal_log_root = seal.get("log_root")
    if not seal_log_root:
        conn.close()
        return False, EXIT_MERKLE_MISMATCH, "MISSING log_root in seal.json â€” possible tampering"
    if computed_log_root != seal_log_root:
        conn.close()
        return False, EXIT_MERKLE_MISMATCH, (
            f"Log Merkle root mismatch: "
            f"computed={computed_log_root[:16]}... "
            f"seal={seal_log_root[:16]}..."
        )

    # --- Step 3: System Root ---
    computed_system_root = compute_system_root(computed_artifact_root, computed_log_root)

    seal_system_root = seal.get("system_root")
    if not seal_system_root:
        conn.close()
        return False, EXIT_MERKLE_MISMATCH, "MISSING system_root in seal.json â€” possible tampering"
    if computed_system_root != seal_system_root:
        conn.close()
        return False, EXIT_MERKLE_MISMATCH, (
            f"System root mismatch: "
            f"computed={computed_system_root[:16]}... "
            f"seal={seal_system_root[:16]}..."
        )

    # --- Step 4: Evidence Root ---
    cursor.execute("SELECT path, size, mtime, sha256 FROM baseline_files ORDER BY path ASC")
    evidence_hashes = [hashlib.sha256(canonical_json({"path": row[0], "size": row[1], "mtime": row[2], "sha256": row[3]})).hexdigest() for row in cursor.fetchall()]
    computed_evidence_root = compute_merkle_root(evidence_hashes)

    seal_evidence_root = seal.get("evidence_root")
    if not seal_evidence_root:
        conn.close()
        return False, EXIT_MERKLE_MISMATCH, "MISSING evidence_root in seal.json â€” possible tampering"
    if computed_evidence_root != seal_evidence_root:
        conn.close()
        return False, EXIT_MERKLE_MISMATCH, (
            f"Evidence root mismatch: "
            f"computed={computed_evidence_root[:16]}... "
            f"seal={seal_evidence_root[:16]}..."
        )

    conn.close()

    # --- Step 5: Cross-check count fields (Fix #9) ---
    seal_artifact_count = seal.get("artifact_count")
    seal_log_count = seal.get("log_entry_count")
    seal_baseline_count = seal.get("baseline_file_count")

    count_issues = []
    if seal_artifact_count is not None and seal_artifact_count != len(artifact_hashes):
        count_issues.append(f"artifact_count: seal={seal_artifact_count} computed={len(artifact_hashes)}")
    if seal_log_count is not None and seal_log_count != len(log_hashes):
        count_issues.append(f"log_entry_count: seal={seal_log_count} computed={len(log_hashes)}")
    if seal_baseline_count is not None and seal_baseline_count != len(evidence_hashes):
        count_issues.append(f"baseline_file_count: seal={seal_baseline_count} computed={len(evidence_hashes)}")

    if count_issues:
        return False, EXIT_MERKLE_MISMATCH, "Count field mismatch: " + "; ".join(count_issues)
    print_result(f"Count Fields: VALID (artifacts={len(artifact_hashes)}, logs={len(log_hashes)}, baseline={len(evidence_hashes)})", "GREEN")

    # --- Step 6: Verify investigator_fingerprint (Fix #5) ---
    seal_fingerprint = seal.get("investigator_fingerprint")
    if seal_fingerprint:
        computed_fingerprint = compute_public_key_fingerprint(pub_key_path)
        if computed_fingerprint and computed_fingerprint != seal_fingerprint:
            return False, EXIT_SIGNATURE_INVALID, (
                f"Investigator fingerprint mismatch: "
                f"seal={seal_fingerprint[:16]}... "
                f"provided_key={computed_fingerprint[:16]}... "
                f"â€” possible key substitution attack!"
            )
        elif computed_fingerprint:
            print_result(f"Investigator Fingerprint: VALID ({computed_fingerprint[:16]}...)", "GREEN")
    else:
        print_result("WARNING: No investigator_fingerprint in seal (legacy bundle)", "YELLOW")

    # --- Step 7: Validate build_hash from parser_version_manifest (Fix #6) ---
    seal_manifest = seal.get("parser_version_manifest")
    seal_build_hash = seal.get("build_hash")
    if seal_manifest and seal_build_hash:
        recomputed_build_hash = hashlib.sha256(canonical_json(seal_manifest)).hexdigest()
        if recomputed_build_hash != seal_build_hash:
            return False, EXIT_VERSION_DRIFT, (
                f"Build hash mismatch: "
                f"seal={seal_build_hash[:16]}... "
                f"recomputed={recomputed_build_hash[:16]}... "
                f"â€” parser_version_manifest may be tampered"
            )
        print_result(f"Parser Manifest Build Hash: VALID ({len(seal_manifest)} plugins)", "GREEN")
    else:
        print_result("WARNING: No parser_version_manifest or build_hash in seal (legacy bundle)", "YELLOW")

    # --- Step 8: Verify tool_version and execution_id (Fix #8) ---
    seal_tool_version = seal.get("tool_version")
    if seal_tool_version:
        print_result(f"Tool Version: {seal_tool_version}", "INFO")
    else:
        print_result("WARNING: No tool_version in seal (legacy bundle)", "YELLOW")

    seal_execution_id = seal.get("execution_id")
    if seal_execution_id and seal_execution_id != "UNKNOWN":
        print_result(f"Execution ID: {seal_execution_id}", "INFO")
    elif seal_execution_id == "UNKNOWN":
        print_result("WARNING: execution_id is UNKNOWN â€” no plugin runs recorded", "YELLOW")
    else:
        print_result("WARNING: No execution_id in seal (legacy bundle)", "YELLOW")

    seal_case_id = seal.get("case_id")
    if seal_case_id:
        print_result(f"Case ID (from seal): {seal_case_id}", "INFO")

    # --- Step 9: Verify Ed25519 Signature ---
    if "signature" in seal:
        signed_payload = _normalize_seal_types(
            {k: v for k, v in seal.items() if k != "signature"}
        )
        payload_bytes = canonical_json(signed_payload)
        signature_b64 = seal["signature"]

        if not verify_ed25519_b64(pub_key_path, payload_bytes, signature_b64):
            return False, EXIT_SIGNATURE_INVALID, "Ed25519 signature verification failed"

        print_result("Cryptographic Signature: VALID", "GREEN")
    else:
        return False, EXIT_SIGNATURE_INVALID, "No signature field found in seal.json"

    print_result(f"Artifact Merkle Root: VALID ({len(artifact_hashes)} artifacts)", "GREEN")
    print_result(f"Log Merkle Root: VALID ({len(log_hashes)} entries)", "GREEN")
    print_result(f"Evidence Merkle Root: VALID ({len(evidence_hashes)} files)", "GREEN")
    print_result(f"System Root: VALID ({computed_system_root[:16]}...)", "GREEN")

    return True, EXIT_OK, "VERIFIED"


def verify_bundle_archive(bundle_path, expected_fingerprint=None, check_evidence=True,
                          progress_cb=None, max_uncompressed_bytes=64 * 1024**3):
    """Verify a received XtractR ZIP without extracting its contents to a case folder.

    Only the SQLite database, seal, public key, and optional custody ledger are copied
    into a temporary directory. All other members are read in place and hashed as
    streams. The key shipped inside the bundle proves internal consistency; an
    expected fingerprint supplied out-of-band is required to authenticate its owner.
    """
    checks = []

    def add(check_id, name, status, message, location=None, issues=None):
        checks.append({"id": check_id, "name": name, "status": status,
                       "message": message, "location": location,
                       "issues": issues or []})

    def finish(case_id=None, signer_fingerprint=None):
        failed = sum(check["status"] == "failed" for check in checks)
        warnings = sum(check["status"] == "warning" for check in checks)
        passed = sum(check["status"] == "passed" for check in checks)
        trusted = any(check["id"] == "identity" and check["status"] == "passed" for check in checks)
        overall = "failed" if failed else ("verified" if warnings == 0 and trusted else "internally_consistent")
        if overall == "verified":
            headline = "Bundle integrity passed and the signer fingerprint matched."
        elif overall == "internally_consistent":
            headline = "No integrity mismatch was found, but review the trust and evidence warnings."
        else:
            headline = "Verification found integrity or trust failures. Review the exact locations below."
        return {"success": True, "overall": overall, "headline": headline,
                "trusted_signer": trusted, "case_id": case_id,
                "signer_fingerprint": signer_fingerprint,
                "summary": {"passed": passed, "warnings": warnings,
                            "failed": failed, "checks": len(checks)},
                "steps": checks}

    def fail_early(check_id, name, message, location=None):
        add(check_id, name, "failed", message, location,
            [{"location": location or "Bundle", "message": message}])
        return finish()

    def safe_member_name(name):
        if (not isinstance(name, str) or not name or "\x00" in name or "\\" in name or name.startswith("/")
                or name.endswith("/") or ":" in name.split("/", 1)[0]):
            return False
        parts = name.split("/")
        return all(part not in ("", ".", "..") for part in parts)

    def read_member(archive, members, name, limit=256 * 1024**2):
        info = members.get(name)
        if info is None:
            raise KeyError(f"Missing required file: {name}")
        if info.file_size > limit:
            raise ValueError(f"{name} exceeds the {limit} byte metadata limit")
        with archive.open(info, "r") as stream:
            data = stream.read(limit + 1)
        if len(data) > limit:
            raise ValueError(f"{name} exceeds the {limit} byte metadata limit")
        return data

    def parse_json_without_duplicate_keys(data):
        def unique_object(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    raise ValueError(f"Duplicate JSON field: {key}")
                value[key] = item
            return value
        return json.loads(data, object_pairs_hook=unique_object)

    def copy_member(archive, members, name, destination):
        info = members[name]
        written = 0
        with archive.open(info, "r") as source, open(destination, "wb") as output:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                output.write(chunk)
                written += len(chunk)
        if written != info.file_size:
            raise ValueError(f"Uncompressed size mismatch for {name}")

    def hash_member(archive, info, algorithms=("sha256",), label="", progress=None):
        digests = {name: hashlib.new(name, usedforsecurity=name not in ("sha1", "md5"))
                   for name in algorithms}
        size = 0
        last_progress = 0
        with archive.open(info, "r") as stream:
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                for digest in digests.values():
                    digest.update(chunk)
                if progress and size - last_progress >= 256 * 1024**2:
                    progress(f"Hashing {label or info.filename}: {size:,} bytes checked")
                    last_progress = size
        return size, {name: digest.hexdigest() for name, digest in digests.items()}

    if expected_fingerprint:
        expected_fingerprint = expected_fingerprint.strip().lower().replace(":", "")
        if not re.fullmatch(r"[0-9a-f]{64}", expected_fingerprint):
            return fail_early("identity", "Trusted signer fingerprint",
                              "Enter a 64-character SHA-256 fingerprint obtained separately from the sender.")

    try:
        with zipfile.ZipFile(bundle_path, "r") as archive:
            infos = archive.infolist()
            if not infos:
                return fail_early("archive", "Bundle archive", "The ZIP archive is empty.")
            if len(infos) > 250_000:
                return fail_early("archive", "Bundle archive", "The ZIP contains more than 250,000 members.")

            invalid_names = [info.filename for info in infos if not safe_member_name(info.filename)]
            names = [info.filename for info in infos]
            duplicates = sorted(name for name, count in Counter(names).items() if count > 1)
            symlinks = [info.filename for info in infos
                        if stat.S_ISLNK((info.external_attr >> 16) & 0xFFFF)]
            encrypted = [info.filename for info in infos if info.flag_bits & 0x1]
            total_uncompressed = sum(info.file_size for info in infos)
            if invalid_names or duplicates or symlinks or encrypted:
                issues = []
                issues.extend({"location": name, "message": "Unsafe or unsupported ZIP path."} for name in invalid_names)
                issues.extend({"location": name, "message": "Duplicate ZIP member name."} for name in duplicates)
                issues.extend({"location": name, "message": "Symbolic links are not accepted in a received bundle."} for name in symlinks)
                issues.extend({"location": name, "message": "Encrypted ZIP members are not supported."} for name in encrypted)
                add("archive", "Bundle archive safety", "failed",
                    f"Rejected {len(issues)} unsafe or ambiguous ZIP member(s).", "ZIP directory", issues[:100])
                return finish()
            if total_uncompressed > max_uncompressed_bytes:
                return fail_early("archive", "Bundle archive size",
                                  f"Uncompressed archive size exceeds the configured {max_uncompressed_bytes} byte limit.",
                                  "ZIP directory")

            members = {info.filename: info for info in infos}
            required = ("manifest.json", "manifest.json.sig", "investigator.pub",
                        "seal.json", "case.db", "evidence_manifest.json", "README_EVIDENCE.md")
            missing = [name for name in required if name not in members]
            if missing:
                return fail_early("archive", "XtractR export structure",
                                  "This ZIP is missing required XtractR export files: " + ", ".join(missing),
                                  "ZIP directory")

            try:
                manifest_bytes = read_member(archive, members, "manifest.json")
                manifest_signature = read_member(archive, members, "manifest.json.sig", 4096).decode("ascii").strip()
                manifest = parse_json_without_duplicate_keys(manifest_bytes)
                if not isinstance(manifest, dict) or not isinstance(manifest.get("files"), dict):
                    raise ValueError("manifest.json must contain a files object")
                if len(manifest["files"]) > 250_000:
                    raise ValueError("manifest.json lists more than 250,000 files")
                inventory_bytes = read_member(archive, members, "evidence_manifest.json")
                inventory = parse_json_without_duplicate_keys(inventory_bytes)
                if not isinstance(inventory, dict) or not isinstance(inventory.get("files"), list):
                    raise ValueError("evidence_manifest.json must contain a files array")
            except (KeyError, ValueError, UnicodeDecodeError, json.JSONDecodeError, zipfile.BadZipFile) as exc:
                return fail_early("metadata", "Bundle metadata", str(exc), "manifest.json / evidence_manifest.json")

            case_id = str(manifest.get("case_id") or inventory.get("case_id") or "Unknown case")
            if inventory.get("case_id") and manifest.get("case_id") != inventory.get("case_id"):
                add("metadata", "Case identity metadata", "failed",
                    "The case identifier differs between the signed manifest and evidence inventory.",
                    "manifest.json / evidence_manifest.json")
            else:
                add("metadata", "Case identity metadata", "passed",
                    f"Bundle identifies case {case_id}.", "manifest.json")

            expected_file_names = set()
            file_issues = []
            for file_index, (name, expected_hash) in enumerate(manifest["files"].items(), 1):
                if not isinstance(name, str) or not safe_member_name(name) or name in ("manifest.json", "manifest.json.sig"):
                    file_issues.append({"location": str(name), "message": "Invalid path in signed manifest."})
                    continue
                expected_file_names.add(name)
                if not isinstance(expected_hash, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", expected_hash):
                    file_issues.append({"location": name, "message": "Manifest SHA-256 value is malformed."})
                    continue
                info = members.get(name)
                if info is None:
                    file_issues.append({"location": name, "expected": expected_hash,
                                        "actual": "missing", "message": "Signed file is missing from the ZIP."})
                    continue
                try:
                    _, actual = hash_member(archive, info, label=name, progress=progress_cb)
                    if actual["sha256"] != expected_hash.lower():
                        file_issues.append({"location": name, "expected": expected_hash,
                                            "actual": actual["sha256"],
                                            "message": "File SHA-256 does not match the signed manifest."})
                except Exception as exc:
                    file_issues.append({"location": name, "message": f"Could not read ZIP member: {exc}"})
                if progress_cb and (file_index == 1 or file_index == len(manifest["files"]) or file_index % 25 == 0):
                    progress_cb(f"Checked {file_index}/{len(manifest['files'])} signed export files")

            for name in ("case.db", "seal.json", "investigator.pub", "evidence_manifest.json", "README_EVIDENCE.md"):
                if name not in expected_file_names:
                    file_issues.append({"location": name, "message": "Required export file is not covered by the signed manifest."})

            actual_fingerprint = None
            with tempfile.TemporaryDirectory(prefix="xtractr-bundle-verify-") as temp_dir:
                public_key_path = os.path.join(temp_dir, "investigator.pub")
                copy_member(archive, members, "investigator.pub", public_key_path)
                with open(os.path.join(temp_dir, "manifest.json"), "wb") as stream:
                    stream.write(manifest_bytes)
                with open(os.path.join(temp_dir, "manifest.json.sig"), "w", encoding="ascii") as stream:
                    stream.write(manifest_signature)

                with open(os.devnull, "w") as sink:
                    from contextlib import redirect_stdout
                    with redirect_stdout(sink):
                        manifest_signature_ok = verify_signature(public_key_path, manifest_bytes, manifest_signature)
                        actual_fingerprint = compute_public_key_fingerprint(public_key_path)
                if manifest_signature_ok:
                    add("manifest-signature", "Signed export manifest", "passed",
                        "Ed25519 signature on manifest.json is valid.", "manifest.json.sig")
                else:
                    add("manifest-signature", "Signed export manifest", "failed",
                        "The manifest signature does not validate with the key included in the bundle.",
                        "manifest.json.sig", [{"location": "manifest.json.sig", "message": "Signature verification failed."}])

                add("manifest-files", "Signed export file inventory", "failed" if file_issues else "passed",
                    f"Checked {len(manifest['files'])} signed export files; found {len(file_issues)} issue(s).",
                    "manifest.json", file_issues[:500])

                identity_issues = []
                if expected_fingerprint:
                    if actual_fingerprint == expected_fingerprint:
                        add("identity", "Out-of-band signer fingerprint", "passed",
                            "The included public key matches the SHA-256 fingerprint supplied separately.",
                            "investigator.pub")
                    else:
                        identity_issues.append({"location": "investigator.pub",
                                                "expected": expected_fingerprint,
                                                "actual": actual_fingerprint or "unavailable",
                                                "message": "The signer key does not match the independently supplied fingerprint."})
                        add("identity", "Out-of-band signer fingerprint", "failed",
                            "The bundle signer is different from the trusted fingerprint you supplied.",
                            "investigator.pub", identity_issues)
                elif actual_fingerprint:
                    add("identity", "Signer identity", "warning",
                        "The signature is checked against a key inside the bundle, but the sender is not authenticated. Compare this fingerprint with one received through a separate trusted channel.",
                        "investigator.pub", [{"location": "SHA-256 public-key fingerprint",
                                              "actual": actual_fingerprint,
                                              "message": "The included key alone is not a trust anchor."}])
                else:
                    add("identity", "Signer identity", "failed",
                        "The public key in the bundle could not be read.", "investigator.pub")

                # The archive is never extracted wholesale. Only verifier inputs are
                # copied to this private temporary directory, then deleted on exit.
                for name in ("case.db", "seal.json"):
                    copy_member(archive, members, name, os.path.join(temp_dir, name))
                ledger_name = next((name for name in members
                                    if "/" not in name and name.endswith("_custody_ledger.jsonl")), None)
                if ledger_name:
                    copy_member(archive, members, ledger_name, os.path.join(temp_dir, ledger_name))

                with open(os.devnull, "w") as sink:
                    from contextlib import redirect_stdout
                    with redirect_stdout(sink):
                        database_ok = check_sqlite_integrity(os.path.join(temp_dir, "case.db"))
                add("database", "SQLite database integrity", "passed" if database_ok else "failed",
                    "SQLite integrity_check passed." if database_ok else "SQLite reported database corruption.",
                    "case.db", [] if database_ok else [{"location": "case.db", "message": "SQLite integrity_check failed."}])

                with open(os.devnull, "w") as sink:
                    from contextlib import redirect_stdout
                    with redirect_stdout(sink):
                        seal_ok, exit_code, reason = verify_merkle_seal(temp_dir, public_key_path)
                add("seal", "Cryptographic seal and Merkle roots", "passed" if seal_ok else "failed",
                    "Seal signature, evidence/artifact/log roots, and recorded counts are consistent." if seal_ok else f"Seal verification failed (code {exit_code}): {reason}",
                    "seal.json / case.db", [] if seal_ok else [{"location": "seal.json / case.db",
                                                                  "message": reason, "exit_code": exit_code}])

                if ledger_name:
                    with open(os.devnull, "w") as sink:
                        from contextlib import redirect_stdout
                        with redirect_stdout(sink):
                            ledger_ok, mismatch_count = verify_jsonl_ledger(temp_dir, os.path.join(temp_dir, "case.db"))
                    add("custody-ledger", "JSONL and SQLite custody ledger", "passed" if ledger_ok else "failed",
                        "All JSONL custody records match the SQLite ledger." if ledger_ok else f"Found {mismatch_count} custody ledger mismatch(es).",
                        ledger_name, [] if ledger_ok else [{"location": ledger_name,
                                                           "message": f"Found {mismatch_count} mismatching field(s)."}])
                else:
                    add("custody-ledger", "JSONL custody ledger", "warning",
                        "No JSONL custody ledger is included in this bundle.", "ZIP directory")

            inventory_issues = []
            algorithms = inventory.get("hash_algorithms")
            known_algorithms = ("sha256", "sha512", "sha384", "sha1", "md5")
            if not isinstance(algorithms, list) or tuple(algorithms) != known_algorithms:
                inventory_issues.append({"location": "evidence_manifest.json / hash_algorithms",
                                         "message": "The evidence inventory must list exactly SHA-256, SHA-512, SHA-384, SHA-1, and MD5 in the supported order."})
                algorithms = []
            if len(inventory["files"]) > 250_000:
                inventory_issues.append({"location": "evidence_manifest.json / files",
                                         "message": "Evidence inventory exceeds 250,000 files."})
                records = []
            else:
                records = inventory["files"]
            expected_evidence_count = manifest.get("evidence_file_count")
            if (not isinstance(expected_evidence_count, int) or isinstance(expected_evidence_count, bool)
                    or expected_evidence_count != len(inventory["files"])):
                inventory_issues.append({"location": "manifest.json / evidence_file_count",
                                         "expected": expected_evidence_count,
                                         "actual": len(inventory["files"]),
                                         "message": "Signed manifest evidence-file count does not match the inventory."})
            inventory_paths = set()
            payload_paths = set()
            manifest_payload_flag = manifest.get("evidence_payload_included")
            inventory_payload_flag = inventory.get("evidence_payload_included")
            if not isinstance(manifest_payload_flag, bool):
                inventory_issues.append({"location": "manifest.json / evidence_payload_included",
                                         "message": "Signed manifest evidence_payload_included value must be a boolean."})
            if not isinstance(inventory_payload_flag, bool):
                inventory_issues.append({"location": "evidence_manifest.json / evidence_payload_included",
                                         "message": "Inventory evidence_payload_included value must be a boolean."})
            evidence_payload_included = manifest_payload_flag is True
            if evidence_payload_included != inventory_payload_flag:
                inventory_issues.append({"location": "evidence_manifest.json / evidence_payload_included",
                                         "message": "Bundle manifest and evidence inventory disagree about whether evidence bytes are included."})

            evidence_issues = []
            for index, record in enumerate(records, 1):
                if not isinstance(record, dict):
                    inventory_issues.append({"location": f"evidence_manifest.json / files[{index - 1}]",
                                             "message": "Evidence record is not an object."})
                    continue
                path = record.get("path")
                if not isinstance(path, str) or not safe_member_name(path):
                    inventory_issues.append({"location": f"evidence_manifest.json / files[{index - 1}]",
                                             "message": "Evidence path is invalid or unsafe."})
                    continue
                if path in inventory_paths:
                    inventory_issues.append({"location": path, "message": "Duplicate evidence path in inventory."})
                    continue
                inventory_paths.add(path)
                size = record.get("size_bytes")
                hashes = record.get("hashes")
                if not isinstance(size, int) or isinstance(size, bool) or size < 0 or not isinstance(hashes, dict):
                    inventory_issues.append({"location": path, "message": "Evidence size or digest record is malformed."})
                    continue
                if algorithms and any(name not in hashes or not isinstance(hashes[name], str)
                       or not re.fullmatch(r"[0-9a-fA-F]{" + str(hashlib.new(name).digest_size * 2) + r"}", hashes[name])
                       for name in algorithms):
                    inventory_issues.append({"location": path, "message": "One or more evidence digest values are missing or malformed."})
                    continue
                archive_name = "evidence/" + path
                if evidence_payload_included:
                    payload_paths.add(archive_name)
                    info = members.get(archive_name)
                    if info is None:
                        evidence_issues.append({"location": archive_name, "expected": hashes,
                                                "actual": "missing", "message": "Evidence payload file is missing from the ZIP."})
                    elif check_evidence:
                        try:
                            if not algorithms:
                                if not evidence_issues:
                                    evidence_issues.append({"location": "evidence_manifest.json / hash_algorithms",
                                                            "message": "Evidence bytes cannot be compared because the required five-hash inventory is invalid."})
                                continue
                            actual_size, actual_hashes = hash_member(archive, info, tuple(algorithms),
                                                                    label=path, progress=progress_cb)
                            if actual_size != size or any(actual_hashes[name] != hashes[name].lower() for name in algorithms):
                                evidence_issues.append({"location": archive_name, "expected": hashes,
                                                        "actual": actual_hashes,
                                                        "message": "Evidence bytes do not match the five-hash inventory."})
                        except Exception as exc:
                            evidence_issues.append({"location": archive_name,
                                                    "message": f"Could not read evidence bytes: {exc}"})
                    if progress_cb and (index == 1 or index == len(records) or index % 50 == 0):
                        progress_cb(f"Checking evidence payload: {index}/{len(records)} files")
                elif "evidence/" + path in members:
                    inventory_issues.append({"location": archive_name,
                                             "message": "Bundle contains evidence bytes but its signed manifest says they were omitted."})

            add("evidence-inventory", "Evidence hash inventory", "failed" if inventory_issues else "passed",
                f"Read {len(inventory_paths)} source-file records with {len(algorithms)} hash algorithms." if not inventory_issues else f"Found {len(inventory_issues)} inventory problem(s).",
                "evidence_manifest.json", inventory_issues[:500])
            if not evidence_payload_included:
                add("evidence-payload", "Evidence payload comparison", "warning",
                    "This bundle contains the signed hash inventory but not the source file bytes. The actual evidence cannot be compared until you obtain the source files separately.",
                    "evidence/", [])
            elif not check_evidence:
                add("evidence-payload", "Evidence payload comparison", "failed" if evidence_issues else "warning",
                    f"Found {len(evidence_issues)} missing payload file(s); other source bytes were not re-hashed." if evidence_issues else "The source bytes were not re-hashed because this check was disabled.",
                    "evidence/", evidence_issues[:500])
            else:
                add("evidence-payload", "Evidence payload hashes", "failed" if evidence_issues else "passed",
                    f"Compared the included bytes for {len(payload_paths)} source files against the five-digest inventory; found {len(evidence_issues)} mismatch(es).",
                    "evidence/", evidence_issues[:500])

            expected_members = expected_file_names | {"manifest.json", "manifest.json.sig"} | payload_paths
            extra_members = sorted(set(members) - expected_members)
            add("unlisted-members", "Unlisted ZIP members", "failed" if extra_members else "passed",
                f"Found {len(extra_members)} unlisted ZIP member(s)." if extra_members else "Every ZIP member is covered by the signed manifest or evidence inventory.",
                "ZIP directory", [{"location": name, "message": "Member is not listed in the signed bundle."}
                                  for name in extra_members[:500]])

            tsa_info = members.get("seal_tsa.tsr")
            if tsa_info:
                add("timestamp", "RFC 3161 timestamp token", "warning",
                    f"Token is present ({tsa_info.file_size} bytes), but response status, imprint, nonce, and TSA certificate chain are not validated.",
                    "seal_tsa.tsr")
            else:
                add("timestamp", "RFC 3161 timestamp token", "info",
                    "No external timestamp token is included.", "seal_tsa.tsr")
            return finish(case_id, actual_fingerprint)
    except Exception as exc:
        if not checks:
            return fail_early("archive", "Bundle archive", f"Could not read this ZIP: {exc}", os.path.basename(bundle_path))
        add("archive-read", "Bundle archive read", "failed", str(exc), os.path.basename(bundle_path),
            [{"location": os.path.basename(bundle_path), "message": str(exc)}])
        return finish()


def main():
    parser = argparse.ArgumentParser(description="XtractR Independent Verifier")
    subparsers = parser.add_subparsers(dest="command")

    bundle_parser = subparsers.add_parser("verify-bundle", help="Verify a received XtractR ZIP bundle")
    bundle_parser.add_argument("bundle_path", help="Path to the received .zip bundle")
    bundle_parser.add_argument("--expect-fingerprint", help="Trusted SHA-256 public-key fingerprint received separately")
    bundle_parser.add_argument("--allow-unpinned", action="store_true",
                               help="Allow integrity-only verification when no trusted fingerprint is available")
    bundle_parser.add_argument("--skip-evidence", action="store_true",
                               help="Skip hashing included evidence payload bytes")

    # New-style: xtractr_verify.py verify <case_dir> --pub-key <path>
    verify_parser = subparsers.add_parser("verify", help="Verify a case directory")
    verify_parser.add_argument("case_dir", help="Path to case directory")
    verify_parser.add_argument("--pub-key", required=False, help="Investigator Public Key")
    verify_parser.add_argument("--cert", required=False, help="Investigator X.509 Certificate (alternative to --pub-key)")
    verify_parser.add_argument("--strict", action="store_true", help="Strict mode: reject expired certificates")
    verify_parser.add_argument("--expect-fingerprint", help="Out-of-band trusted investigator key fingerprint (SHA-256)")
    verify_parser.add_argument("--allow-unpinned", action="store_true", help="Verify internal consistency while reporting signer as unauthenticated")

    # Legacy: xtractr_verify.py --case-dir <dir> --pub-key <path>
    parser.add_argument("--case-dir", help="Path to case directory (legacy)")
    parser.add_argument("--pub-key", help="Investigator Public Key (legacy)")
    parser.add_argument("--cert", help="Investigator X.509 Certificate")
    parser.add_argument("--strict", action="store_true", help="Strict mode: reject expired certificates")
    parser.add_argument("--expect-fingerprint", help="Out-of-band trusted investigator key fingerprint (SHA-256)")
    parser.add_argument("--allow-unpinned", action="store_true", help="Verify internal consistency while reporting signer as unauthenticated")

    args = parser.parse_args()

    if args.command == "verify-bundle":
        result = verify_bundle_archive(
            args.bundle_path,
            expected_fingerprint=args.expect_fingerprint,
            check_evidence=not args.skip_evidence,
        )
        for check in result["steps"]:
            level = {"passed": "GREEN", "warning": "YELLOW", "info": "INFO", "failed": "RED"}.get(check["status"], "INFO")
            print_result(f"{check['name']}: {check['message']}", level)
            for issue in check.get("issues", []):
                print_result(f"  {issue.get('location', check.get('location', ''))}: {issue.get('message', '')}",
                             "RED" if check["status"] == "failed" else level)
        print_result(result["headline"], "RED" if result["overall"] == "failed" else "GREEN" if result["overall"] == "verified" else "YELLOW")
        if result["overall"] == "failed" or (not result["trusted_signer"] and not args.allow_unpinned):
            sys.exit(EXIT_SIGNATURE_INVALID if not result["trusted_signer"] else EXIT_GENERAL)
        sys.exit(EXIT_OK)

    # Resolve case_dir and pub_key from either mode
    if args.command == "verify":
        case_dir = args.case_dir
        pub_key = args.pub_key
        cert = args.cert
        strict = args.strict
        expected_fingerprint = args.expect_fingerprint
        allow_unpinned = args.allow_unpinned
    elif args.case_dir and (args.pub_key or args.cert):
        case_dir = args.case_dir
        pub_key = args.pub_key
        cert = args.cert
        strict = getattr(args, 'strict', False)
        expected_fingerprint = args.expect_fingerprint
        allow_unpinned = args.allow_unpinned
    else:
        parser.print_help()
        sys.exit(1)

    # Resolve public key from certificate if provided
    temp_pub_key = None
    try:
        if cert:
            print_result("Loading public key from X.509 certificate...", "INFO")
            temp_pub_key = load_public_key_from_cert(cert, strict=strict)
            if not temp_pub_key:
                print_result("Failed to extract public key from certificate", "RED")
                sys.exit(EXIT_GENERAL)
            pub_key = temp_pub_key
        elif not pub_key:
            # Auto-detect public key â€” search multiple locations (Fix #1)
            search_paths = [
                os.path.join(case_dir, "investigator.pub"),         # exported bundle
                os.path.join(case_dir, "keys", "investigator.pub"), # raw case dir
            ]
            pub_key = None
            for candidate in search_paths:
                if os.path.exists(candidate):
                    pub_key = candidate
                    print_result(f"Auto-detected public key: {candidate}", "INFO")
                    break

            if not pub_key:
                # Also try auto-detecting certificate
                cert_paths = [
                    os.path.join(case_dir, "investigator.crt"),
                    os.path.join(case_dir, "keys", "investigator.crt"),
                ]
                for candidate in cert_paths:
                    if os.path.exists(candidate):
                        print_result(f"Auto-detected certificate: {candidate}", "INFO")
                        temp_pub_key = load_public_key_from_cert(candidate, strict=strict)
                        if temp_pub_key:
                            pub_key = temp_pub_key
                            break

            if not pub_key:
                print_result("No --pub-key or --cert provided and no investigator.pub/crt found in case dir or keys/", "RED")
                sys.exit(EXIT_GENERAL)

        REQUIRED_FILES = [
            "case.db", "seal.json",
        ]

        # 1. Existence Check
        print_result("=" * 60, "INFO")
        print_result("XtractR Independent Verifier", "INFO")
        print_result("=" * 60, "INFO")
        print_result(f"Case Directory: {os.path.abspath(case_dir)}", "INFO")
        print_result(f"Public Key: {pub_key}", "INFO")
        print_result("=" * 60, "INFO")

        print_result("Checking Essential Files...", "INFO")
        for fname in REQUIRED_FILES:
            if not os.path.exists(os.path.join(case_dir, fname)):
                print_result(f"MISSING CRITICAL FILE: {fname}", "RED")
                sys.exit(EXIT_GENERAL)

        # 2. SQLite Integrity Check (Fix #16)
        db_path = os.path.join(case_dir, "case.db")
        if not check_sqlite_integrity(db_path):
            print_result("SQLite database corruption detected â€” aborting verification", "RED")
            sys.exit(EXIT_GENERAL)

        actual_fingerprint = compute_public_key_fingerprint(pub_key)
        signer_authenticated = False
        if expected_fingerprint:
            if not actual_fingerprint or actual_fingerprint.lower().replace(":", "") != expected_fingerprint.lower().replace(":", ""):
                print_result("Trusted investigator fingerprint mismatch", "RED")
                sys.exit(EXIT_SIGNATURE_INVALID)
            print_result(f"Pinned investigator fingerprint: {actual_fingerprint}", "INFO")
            signer_authenticated = True
        elif not allow_unpinned:
            print_result("Signer is not authenticated: supply --expect-fingerprint from an out-of-band trusted source, or explicitly use --allow-unpinned", "RED")
            sys.exit(EXIT_SIGNATURE_INVALID)
        else:
            print_result(f"Signer unauthenticated; bundle key fingerprint: {actual_fingerprint}", "YELLOW")

        # 3. Verify Manifest Signature (if present)
        man_path = os.path.join(case_dir, "manifest.json")
        if os.path.exists(man_path) and os.path.exists(man_path + ".sig"):
            print_result("Verifying Manifest Signature...", "INFO")
            with open(man_path, "rb") as f:
                man_data = f.read()
            with open(man_path + ".sig", "r") as f:
                man_sig = f.read().strip()

            if not verify_signature(pub_key, man_data, man_sig):
                print_result("MANIFEST SIGNATURE INVALID!", "RED")
                sys.exit(EXIT_SIGNATURE_INVALID)
            print_result("Manifest Signature: VALID", "GREEN")

            # 3b. Verify all files in manifest
            print_result("Verifying Bundle Content Hashes...", "INFO")
            manifest = json.loads(man_data)
            all_valid = True

            for fname, expected_hash in manifest.get("files", {}).items():
                fpath = os.path.join(case_dir, fname)
                if not os.path.exists(fpath):
                    print_result(f"Missing file: {fname}", "RED")
                    all_valid = False
                    continue
                actual_hash = compute_hash(fpath)
                if actual_hash != expected_hash:
                    print_result(f"HASH MISMATCH: {fname}", "RED")
                    all_valid = False

            if not all_valid:
                print_result("Bundle Content Corruption Detected!", "RED")
                sys.exit(EXIT_MERKLE_MISMATCH)
            print_result("All Bundle Files Verified against Manifest", "GREEN")

            if manifest.get("evidence_payload_included"):
                inventory_path = os.path.join(case_dir, "evidence_manifest.json")
                if not os.path.isfile(inventory_path):
                    print_result("Evidence payload is marked included, but evidence_manifest.json is missing", "RED")
                    sys.exit(EXIT_MERKLE_MISMATCH)
                with open(inventory_path, "r", encoding="utf-8") as stream:
                    evidence_inventory = json.load(stream)
                algorithms = ("sha256", "sha512", "sha384", "sha1", "md5")
                evidence_ok = True
                for record in evidence_inventory.get("files", []):
                    relative = record.get("path", "").replace("\\", "/")
                    parts = relative.split("/")
                    if not relative or relative.startswith("/") or any(part in ("", ".", "..") for part in parts) or ":" in parts[0]:
                        print_result(f"Unsafe path in evidence inventory: {relative!r}", "RED")
                        evidence_ok = False
                        continue
                    member_path = os.path.join(case_dir, "evidence", *parts)
                    if not os.path.isfile(member_path):
                        print_result(f"Missing evidence file: evidence/{relative}", "RED")
                        evidence_ok = False
                        continue
                    digests = {name: hashlib.new(name, usedforsecurity=name not in ("md5", "sha1")) for name in algorithms}
                    size = 0
                    with open(member_path, "rb") as member:
                        while True:
                            chunk = member.read(1024 * 1024)
                            if not chunk:
                                break
                            size += len(chunk)
                            for digest in digests.values():
                                digest.update(chunk)
                    actual = {name: digest.hexdigest() for name, digest in digests.items()}
                    if size != record.get("size_bytes") or actual != record.get("hashes"):
                        print_result(f"Evidence mismatch at evidence/{relative}: expected={record.get('hashes')} actual={actual}", "RED")
                        evidence_ok = False
                if not evidence_ok:
                    sys.exit(EXIT_MERKLE_MISMATCH)
                print_result(f"Evidence Payload: VALID ({len(evidence_inventory.get('files', []))} files; SHA-256, SHA-512, SHA-384, SHA-1, MD5)", "GREEN")
            else:
                print_result("Evidence payload was not included; only its signed hash inventory is available", "YELLOW")

        # 4. Verify artifact signatures
        SIGNED_ARTIFACTS = [
            "case.db", "seal.json", "report.html", "correlation.json",
        ]

        print_result("Verifying Artifact Signatures...", "INFO")
        for artifact in SIGNED_ARTIFACTS:
            fpath = os.path.join(case_dir, artifact)
            if os.path.exists(fpath):
                sig_path = fpath + ".sig"
                if os.path.exists(sig_path):
                    with open(fpath, "rb") as f:
                        data = f.read()
                    with open(sig_path, "r") as f:
                        sig = f.read().strip()

                    if not verify_signature(pub_key, data, sig):
                        print_result(f"INVALID SIGNATURE: {artifact}", "RED")
                        sys.exit(EXIT_SIGNATURE_INVALID)
                    print_result(f"Signature VALID: {artifact}", "GREEN")

        # 5. Verify Ledger
        print_result("Verifying Seal Logic...", "INFO")
        ledger_valid, ledger_tip = verify_ledger(os.path.join(case_dir, "case.db"))
        if not ledger_valid:
            sys.exit(EXIT_MERKLE_MISMATCH)

        # 5b. JSONL Cross-Validation
        jsonl_valid, jsonl_mismatches = verify_jsonl_ledger(case_dir, os.path.join(case_dir, "case.db"))
        if not jsonl_valid:
            print_result(f"JSONL cross-validation failed with {jsonl_mismatches} mismatches", "RED")
            sys.exit(EXIT_JSONL_MISMATCH)

        # 6. Full Merkle Seal Verification (includes fingerprint, build_hash, counts, signature)
        success, exit_code, reason = verify_merkle_seal(case_dir, pub_key)
        if not success:
            print_result(f"SEAL VERIFICATION FAILED: {reason}", "RED")
            sys.exit(exit_code)

        # 7. TSA Token Presence Check
        tsa_path = os.path.join(case_dir, "seal_tsa.tsr")
        if os.path.exists(tsa_path):
            tsa_size = os.path.getsize(tsa_path)
            
            print_result(f"TSA Token Present: {tsa_size} bytes; signature, imprint, nonce, and trust chain are not validated", "YELLOW")
        else:
            print_result("TSA Token: NOT PRESENT (local time only â€” degraded trust)", "YELLOW")

        verdict = "VERIFIED" if signer_authenticated else "INTERNALLY CONSISTENT; SIGNER UNAUTHENTICATED"
        verdict_color = "GREEN" if signer_authenticated else "YELLOW"
        print_result("=" * 60, verdict_color)
        print_result(f"--- {verdict} ---", verdict_color)
        print_result("=" * 60, verdict_color)

        sys.exit(EXIT_OK)

    finally:
        # Cleanup temp pub key from cert (Fix #13 â€” guaranteed cleanup)
        if temp_pub_key and os.path.exists(temp_pub_key):
            try:
                os.unlink(temp_pub_key)
            except Exception:
                pass


def self_test_integrity_parity():
    """
    Fix #12: Cross-check that verifier's duplicated functions produce
    identical output to core.integrity module.
    
    Run: python xtractr_verify.py self-test
    """
    print_result("Running Implementation Parity Self-Test...", "INFO")
    print_result("Comparing verifier functions against core.integrity...", "INFO")

    try:
        from core.integrity import (
            canonical_json as core_canonical_json,
            compute_merkle_root as core_compute_merkle_root,
            compute_system_root as core_compute_system_root,
            hash_artifact as core_hash_artifact,
        )
    except ImportError as e:
        print_result(
            f"Cannot import core.integrity â€” self-test requires running from XtractR project root: {e}",
            "YELLOW"
        )
        return False

    failures = 0

    # Test 1: canonical_json
    test_objects = [
        {"b": 2, "a": 1},
        {"nested": {"z": 26, "a": 1}, "list": [3, 1, 2]},
        {"int_field": 12345, "str_field": "hello", "none_field": None},
        {},
    ]
    for i, obj in enumerate(test_objects):
        v_result = canonical_json(obj)
        c_result = core_canonical_json(obj)
        if v_result != c_result:
            print_result(f"PARITY FAIL: canonical_json test {i}: verifier={v_result!r} core={c_result!r}", "RED")
            failures += 1
    print_result(f"canonical_json: {len(test_objects)} tests", "GREEN" if failures == 0 else "RED")

    # Test 2: compute_merkle_root
    test_hash_sets = [
        [],
        ["abc123"],
        ["abc123", "def456"],
        ["abc123", "def456", "789ghi"],
        ["z" * 64, "a" * 64, "m" * 64, "f" * 64],
    ]
    mr_failures = 0
    for i, hashes in enumerate(test_hash_sets):
        v_result = compute_merkle_root(hashes)
        c_result = core_compute_merkle_root(hashes)
        if v_result != c_result:
            print_result(f"PARITY FAIL: compute_merkle_root test {i}: verifier={v_result[:16]}... core={c_result[:16]}...", "RED")
            mr_failures += 1
    failures += mr_failures
    print_result(f"compute_merkle_root: {len(test_hash_sets)} tests", "GREEN" if mr_failures == 0 else "RED")

    # Test 3: compute_system_root
    test_root_pairs = [
        ("a" * 64, "b" * 64),
        ("0" * 64, "f" * 64),
        ("abc123", "def456"),
    ]
    sr_failures = 0
    for i, (ar, lr) in enumerate(test_root_pairs):
        v_result = compute_system_root(ar, lr)
        c_result = core_compute_system_root(ar, lr)
        if v_result != c_result:
            print_result(f"PARITY FAIL: compute_system_root test {i}", "RED")
            sr_failures += 1
    failures += sr_failures
    print_result(f"compute_system_root: {len(test_root_pairs)} tests", "GREEN" if sr_failures == 0 else "RED")

    # Test 4: hash_artifact
    test_artifacts = [
        {"artifact_type": "sms", "sha256": "abc", "source_path": "/a", "output_path": "/b",
         "plugin_name": "sms_parser", "plugin_version": "1.0", "timestamp_utc": 1234567890,
         "details": "test", "actor": "SYSTEM"},
        {},
    ]
    ha_failures = 0
    for i, art in enumerate(test_artifacts):
        v_result = hash_artifact(art)
        c_result = core_hash_artifact(art)
        if v_result != c_result:
            print_result(f"PARITY FAIL: hash_artifact test {i}", "RED")
            ha_failures += 1
    failures += ha_failures
    print_result(f"hash_artifact: {len(test_artifacts)} tests", "GREEN" if ha_failures == 0 else "RED")

    # Summary
    total_tests = len(test_objects) + len(test_hash_sets) + len(test_root_pairs) + len(test_artifacts)
    if failures == 0:
        print_result(f"PARITY SELF-TEST PASSED: All {total_tests} tests identical", "GREEN")
        return True
    else:
        print_result(f"PARITY SELF-TEST FAILED: {failures}/{total_tests} mismatches detected!", "RED")
        return False


if __name__ == "__main__":
    # Check for self-test subcommand before argparse
    if len(sys.argv) >= 2 and sys.argv[1] == "self-test":
        success = self_test_integrity_parity()
        sys.exit(EXIT_OK if success else EXIT_GENERAL)
    main()
