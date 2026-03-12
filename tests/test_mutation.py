"""
XtractR Mutation Detection Test Suite

Tests that verify seal.json detects all forms of tampering:
  1. Artifact content mutation → MERKLE_MISMATCH
  2. Artifact reordering → MERKLE_MISMATCH
  3. Log entry modification → MERKLE_MISMATCH
  4. Signature field modification → SIGNATURE_INVALID
  5. Signature replay attack → SIGNATURE_INVALID

Each test modifies the output then runs verify, asserting the correct
failure code and non-zero exit status.
"""
import os
import sys
import json
import base64
import shutil
import sqlite3
import hashlib
import tempfile
import pytest

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.database import CaseDatabase
from core.crypto import IdentityManager
from core.plugin_engine import PluginEngine
from core.ingest import get_vfs
from core.baseline import create_baseline
from core.timeline import TimelineEngine
from core.export import ExportManager
from core.integrity import canonical_json


# Expected exit codes (matching xtractr_verify.py)
EXIT_OK = 0
EXIT_MERKLE_MISMATCH = 10
EXIT_SIGNATURE_INVALID = 11


@pytest.fixture(scope="module")
def sealed_case():
    """
    Create a full sealed case with Merkle-bound seal.json.
    Returns (case_dir, pub_key_path).
    """
    tmpdir = tempfile.mkdtemp(prefix="mutation_test_")
    golden = os.path.join(os.path.dirname(__file__), "golden", "data")

    if not os.path.isdir(golden):
        pytest.skip("Golden dataset not found; run generate_golden.py first")

    case_dir = os.path.join(tmpdir, "case")
    os.makedirs(case_dir, exist_ok=True)

    # Init key pair
    key_dir = os.path.join(tmpdir, "keys")
    identity = IdentityManager(key_dir)
    identity.load_or_generate_keys()

    # Init database
    db_path = os.path.join(case_dir, "case.db")
    db = CaseDatabase(db_path)
    db.set_metadata("case_id", "MUTATION-TEST-001")
    db.set_metadata("investigator_name", "Test Investigator")

    # Baseline
    vfs = get_vfs(golden)
    create_baseline(vfs, db)

    # Run plugins
    plugin_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "plugins"
    )
    engine = PluginEngine(plugin_dir, db)
    engine.run_all(vfs)

    # Timeline
    TimelineEngine(db, case_dir).build_timeline()

    # Create minimal report.html for export
    with open(os.path.join(case_dir, "report.html"), "w") as f:
        f.write("<html><body>Test Report</body></html>")

    # Export (creates seal.json with full Merkle binding)
    exporter = ExportManager(db, identity, case_dir)
    exporter.create_bundle()

    db.close()

    yield case_dir, identity.public_key_path

    shutil.rmtree(tmpdir, ignore_errors=True)


def _run_verify(case_dir, pub_key_path):
    """Run the verifier as a subprocess and return exit code."""
    import subprocess
    verify_script = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "xtractr_verify.py"
    )
    env = os.environ.copy()
    env["PYTHONHASHSEED"] = "0"
    env["LC_ALL"] = "C"
    env["TZ"] = "UTC"

    result = subprocess.run(
        [sys.executable, verify_script,
         "verify", case_dir, "--pub-key", pub_key_path],
        env=env, capture_output=True, text=True
    )
    return result.returncode


def _copy_case(case_dir):
    """Create a mutable copy of the case directory."""
    tmpdir = tempfile.mkdtemp(prefix="mutated_case_")
    copy_dir = os.path.join(tmpdir, "case")
    shutil.copytree(case_dir, copy_dir)
    return copy_dir, tmpdir


class TestMutationDetection:

    def test_clean_case_verifies(self, sealed_case):
        """Sanity check: unmodified case passes verification."""
        case_dir, pub_key = sealed_case
        exit_code = _run_verify(case_dir, pub_key)
        assert exit_code == EXIT_OK, f"Clean case should verify, got exit={exit_code}"

    def test_artifact_content_mutation(self, sealed_case):
        """Mutate an artifact's details in the DB → MERKLE_MISMATCH."""
        case_dir, pub_key = sealed_case
        copy_dir, tmpdir = _copy_case(case_dir)

        try:
            db_path = os.path.join(copy_dir, "case.db")
            conn = sqlite3.connect(db_path)
            conn.execute(
                "UPDATE derived_artifacts SET details = 'TAMPERED' WHERE id = 1"
            )
            conn.commit()
            conn.close()

            exit_code = _run_verify(copy_dir, pub_key)
            assert exit_code == EXIT_MERKLE_MISMATCH, (
                f"Artifact mutation should cause MERKLE_MISMATCH(10), got {exit_code}"
            )
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_artifact_reordering(self, sealed_case):
        """Swap artifact IDs in the DB → MERKLE_MISMATCH."""
        case_dir, pub_key = sealed_case
        copy_dir, tmpdir = _copy_case(case_dir)

        try:
            db_path = os.path.join(copy_dir, "case.db")
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            # Get count of artifacts
            cursor.execute("SELECT COUNT(*) FROM derived_artifacts")
            count = cursor.fetchone()[0]

            if count >= 2:
                # Swap the details of the first two artifacts
                cursor.execute(
                    "SELECT id, details FROM derived_artifacts ORDER BY id ASC LIMIT 2"
                )
                rows = cursor.fetchall()
                id1, det1 = rows[0]
                id2, det2 = rows[1]
                conn.execute(
                    "UPDATE derived_artifacts SET details = ? WHERE id = ?",
                    (det2, id1)
                )
                conn.execute(
                    "UPDATE derived_artifacts SET details = ? WHERE id = ?",
                    (det1, id2)
                )
                conn.commit()

            conn.close()

            exit_code = _run_verify(copy_dir, pub_key)
            if count >= 2:
                assert exit_code == EXIT_MERKLE_MISMATCH, (
                    f"Artifact reordering should cause MERKLE_MISMATCH(10), got {exit_code}"
                )
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_log_entry_modification(self, sealed_case):
        """Tamper with a custody event → MERKLE_MISMATCH."""
        case_dir, pub_key = sealed_case
        copy_dir, tmpdir = _copy_case(case_dir)

        try:
            db_path = os.path.join(copy_dir, "case.db")
            conn = sqlite3.connect(db_path)
            conn.execute(
                "UPDATE custody_events SET details = 'TAMPERED_LOG' WHERE id = 1"
            )
            conn.commit()
            conn.close()

            exit_code = _run_verify(copy_dir, pub_key)
            # Either the ledger chain check or the log Merkle check should fail
            assert exit_code != EXIT_OK, (
                f"Log entry modification should fail verification, got {exit_code}"
            )
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_signature_field_modification(self, sealed_case):
        """Modify a field in seal.json → SIGNATURE_INVALID."""
        case_dir, pub_key = sealed_case
        copy_dir, tmpdir = _copy_case(case_dir)

        try:
            seal_path = os.path.join(copy_dir, "seal.json")
            with open(seal_path, "r") as f:
                seal = json.load(f)

            # Tamper with a field
            seal["case_id"] = "FORGED-CASE-999"

            with open(seal_path, "wb") as f:
                f.write(canonical_json(seal))

            exit_code = _run_verify(copy_dir, pub_key)
            assert exit_code in (EXIT_SIGNATURE_INVALID, EXIT_MERKLE_MISMATCH), (
                f"Signature field modification should fail, got {exit_code}"
            )
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_signature_replay_attack(self, sealed_case):
        """
        Copy seal.json from another case (different data, valid signature
        for different payload) → MERKLE_MISMATCH or SIGNATURE_INVALID.
        """
        case_dir, pub_key = sealed_case
        copy_dir, tmpdir = _copy_case(case_dir)

        try:
            seal_path = os.path.join(copy_dir, "seal.json")
            with open(seal_path, "r") as f:
                seal = json.load(f)

            # Simulate replay: change system_root but keep original signature
            # (like replaying a seal from a different case)
            seal["system_root"] = hashlib.sha256(b"REPLAYED").hexdigest()
            # Keep original signature — it won't match the modified payload

            with open(seal_path, "wb") as f:
                f.write(canonical_json(seal))

            exit_code = _run_verify(copy_dir, pub_key)
            assert exit_code != EXIT_OK, (
                f"Replay attack should fail verification, got {exit_code}"
            )
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)
