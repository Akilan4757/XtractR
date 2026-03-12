"""
XtractR Independent Verifier — Cryptographic Seal Verification

Supports two modes:
  1. xtractr_verify.py verify <case_dir> --pub-key <path>
  2. xtractr_verify.py --case-dir <dir> --pub-key <path>  (legacy)

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

    leaves = sorted(hashes)
    current_level = leaves

    while len(current_level) > 1:
        next_level = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            right = current_level[i + 1] if i + 1 < len(current_level) else left
            combined = hashlib.sha256((left + right).encode('utf-8')).hexdigest()
            next_level.append(combined)
        current_level = next_level

    return current_level[0]


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

        # Auto-detect encoding (Fix #2 — eliminate fragile dual-function API)
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
                print_result("Certificate EXPIRED or NOT YET VALID — STRICT mode: REJECTING", "RED")
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
        print_result("JSONL ledger not found — skipping cross-validation (legacy bundle)", "YELLOW")
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

    # Compare each entry — ALL fields, not just hash
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
        return False, EXIT_MERKLE_MISMATCH, "MISSING artifact_root in seal.json — possible tampering"
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
        return False, EXIT_MERKLE_MISMATCH, "MISSING log_root in seal.json — possible tampering"
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
        return False, EXIT_MERKLE_MISMATCH, "MISSING system_root in seal.json — possible tampering"
    if computed_system_root != seal_system_root:
        conn.close()
        return False, EXIT_MERKLE_MISMATCH, (
            f"System root mismatch: "
            f"computed={computed_system_root[:16]}... "
            f"seal={seal_system_root[:16]}..."
        )

    # --- Step 4: Evidence Root ---
    cursor.execute("SELECT sha256 FROM baseline_files ORDER BY path ASC")
    evidence_hashes = [row[0] for row in cursor.fetchall()]
    computed_evidence_root = compute_merkle_root(evidence_hashes)

    seal_evidence_root = seal.get("evidence_root")
    if not seal_evidence_root:
        conn.close()
        return False, EXIT_MERKLE_MISMATCH, "MISSING evidence_root in seal.json — possible tampering"
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
                f"— possible key substitution attack!"
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
                f"— parser_version_manifest may be tampered"
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
        print_result("WARNING: execution_id is UNKNOWN — no plugin runs recorded", "YELLOW")
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


def main():
    parser = argparse.ArgumentParser(description="XtractR Independent Verifier")
    subparsers = parser.add_subparsers(dest="command")

    # New-style: xtractr_verify.py verify <case_dir> --pub-key <path>
    verify_parser = subparsers.add_parser("verify", help="Verify a case directory")
    verify_parser.add_argument("case_dir", help="Path to case directory")
    verify_parser.add_argument("--pub-key", required=False, help="Investigator Public Key")
    verify_parser.add_argument("--cert", required=False, help="Investigator X.509 Certificate (alternative to --pub-key)")
    verify_parser.add_argument("--strict", action="store_true", help="Strict mode: reject expired certificates")

    # Legacy: xtractr_verify.py --case-dir <dir> --pub-key <path>
    parser.add_argument("--case-dir", help="Path to case directory (legacy)")
    parser.add_argument("--pub-key", help="Investigator Public Key (legacy)")
    parser.add_argument("--cert", help="Investigator X.509 Certificate")
    parser.add_argument("--strict", action="store_true", help="Strict mode: reject expired certificates")

    args = parser.parse_args()

    # Resolve case_dir and pub_key from either mode
    if args.command == "verify":
        case_dir = args.case_dir
        pub_key = args.pub_key
        cert = args.cert
        strict = args.strict
    elif args.case_dir and (args.pub_key or args.cert):
        case_dir = args.case_dir
        pub_key = args.pub_key
        cert = args.cert
        strict = getattr(args, 'strict', False)
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
            # Auto-detect public key — search multiple locations (Fix #1)
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
            print_result("SQLite database corruption detected — aborting verification", "RED")
            sys.exit(EXIT_GENERAL)

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

        # 4. Verify artifact signatures
        SIGNED_ARTIFACTS = [
            "case.db", "seal.json", "report.html",
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
            print_result(f"TSA Token Present: {tsa_size} bytes (external time anchor — NOT cryptographically verified by this tool)", "GREEN")
        else:
            print_result("TSA Token: NOT PRESENT (local time only — degraded trust)", "YELLOW")

        print_result("=" * 60, "GREEN")
        print_result("--- VERIFICATION SUCCESSFUL ---", "GREEN")
        print_result("=" * 60, "GREEN")

        sys.exit(EXIT_OK)

    finally:
        # Cleanup temp pub key from cert (Fix #13 — guaranteed cleanup)
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
            f"Cannot import core.integrity — self-test requires running from XtractR project root: {e}",
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
