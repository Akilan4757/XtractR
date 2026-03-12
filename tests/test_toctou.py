"""
TOCTOU Attack Detection Test

Verifies that the export flow detects evidence file modifications
that occur between baseline and export (Time-of-Check Time-of-Use).

Test flow:
  1. Create a case with baseline
  2. Modify a physical evidence file AFTER baseline
  3. Attempt export
  4. Assert export aborts with exit code 10
"""
import os
import sys
import shutil
import tempfile
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.database import CaseDatabase
from core.crypto import IdentityManager
from core.ingest import get_vfs
from core.baseline import create_baseline
from core.export import ExportManager


@pytest.fixture
def toctou_case():
    """Create a case with evidence that will be tampered with."""
    tmpdir = tempfile.mkdtemp(prefix="toctou_test_")

    # Create fake evidence directory
    evidence_dir = os.path.join(tmpdir, "evidence")
    os.makedirs(evidence_dir)

    # Create evidence files
    file1 = os.path.join(evidence_dir, "important_evidence.txt")
    with open(file1, "w") as f:
        f.write("Original evidence content - untouched")

    file2 = os.path.join(evidence_dir, "phone_dump.bin")
    with open(file2, "wb") as f:
        f.write(b"\x00" * 1024)

    # Setup case
    case_dir = os.path.join(tmpdir, "case")
    os.makedirs(case_dir)

    key_dir = os.path.join(tmpdir, "keys")
    identity = IdentityManager(key_dir)
    identity.load_or_generate_keys(b"test_passphrase_123")

    db = CaseDatabase(os.path.join(case_dir, "case.db"))
    db.set_metadata("case_id", "TOCTOU-TEST-001")
    db.set_metadata("source_path", evidence_dir)

    # Baseline the evidence
    vfs = get_vfs(evidence_dir)
    create_baseline(vfs, db)

    # Create required export files
    for fname in ["report.html"]:
        with open(os.path.join(case_dir, fname), "w") as f:
            f.write("stub")

    yield {
        "tmpdir": tmpdir,
        "evidence_dir": evidence_dir,
        "case_dir": case_dir,
        "db": db,
        "identity": identity,
        "file1": file1,
        "file2": file2,
    }

    db.close()
    shutil.rmtree(tmpdir, ignore_errors=True)


class TestTOCTOU:
    def test_clean_export_succeeds(self, toctou_case):
        """Unmodified evidence should export successfully."""
        exporter = ExportManager(
            toctou_case["db"], toctou_case["identity"], toctou_case["case_dir"]
        )
        # Should not raise
        path = exporter.create_bundle()
        assert os.path.exists(path)

    def test_tampered_file_aborts_export(self, toctou_case):
        """Modified evidence file should cause export to abort."""
        # TAMPER: modify evidence after baseline
        with open(toctou_case["file1"], "w") as f:
            f.write("TAMPERED CONTENT - this was changed after baseline!")

        exporter = ExportManager(
            toctou_case["db"], toctou_case["identity"], toctou_case["case_dir"]
        )

        with pytest.raises(SystemExit) as exc_info:
            exporter.create_bundle()

        assert exc_info.value.code == 10, (
            f"Expected exit code 10 (TOCTOU_TAMPER_DETECTED), got {exc_info.value.code}"
        )

    def test_binary_file_tamper_detected(self, toctou_case):
        """Even single-byte changes in binary files should be detected."""
        # TAMPER: flip one byte in binary file
        with open(toctou_case["file2"], "r+b") as f:
            f.seek(512)
            f.write(b"\xFF")

        exporter = ExportManager(
            toctou_case["db"], toctou_case["identity"], toctou_case["case_dir"]
        )

        with pytest.raises(SystemExit) as exc_info:
            exporter.create_bundle()

        assert exc_info.value.code == 10
