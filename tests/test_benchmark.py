"""
XtractR Benchmark Runner — Parser Accuracy Validation

Tests parser output against the golden dataset ground truth.
Measures: artifact count accuracy, field-level accuracy, recall/precision.
"""
import os
import sys
import json
import sqlite3
import tempfile
import shutil
import pytest

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from core.database import CaseDatabase
from core.plugin_engine import PluginEngine
from core.vfs.directory import DirectoryVFS
from core.baseline import create_baseline


GOLDEN_DIR = os.path.join(os.path.dirname(__file__), "golden", "data")
GROUND_TRUTH_PATH = os.path.join(os.path.dirname(__file__), "golden", "ground_truth.json")


@pytest.fixture
def golden_run(tmp_path):
    """Execute all plugins against the golden dataset and return artifacts + ground truth."""
    # Setup case
    case_dir = str(tmp_path / "benchmark_case")
    os.makedirs(case_dir, exist_ok=True)
    db_path = os.path.join(case_dir, "case.db")
    db = CaseDatabase(db_path)
    db.set_metadata("case_id", "BENCHMARK-GOLDEN-001")
    
    # Create VFS and baseline
    vfs = DirectoryVFS(GOLDEN_DIR)
    create_baseline(vfs, db)
    
    # Run plugins
    plugin_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "plugins")
    engine = PluginEngine(plugin_dir, db)
    artifacts = engine.run_all(vfs)
    
    # Load ground truth
    with open(GROUND_TRUTH_PATH) as f:
        ground_truth = json.load(f)
    
    # Query plugin_runs for status
    cursor = db._conn.cursor()
    cursor.execute("SELECT plugin_name, status, artifacts_count FROM plugin_runs")
    runs = {row["plugin_name"]: {"status": row["status"], "count": row["artifacts_count"]} for row in cursor.fetchall()}
    
    yield {
        "artifacts": artifacts,
        "ground_truth": ground_truth,
        "plugin_runs": runs,
        "db": db,
        "case_dir": case_dir,
    }
    
    db.close()


class TestParserAccuracy:
    """Test each parser's accuracy against known ground truth."""
    
    def test_sms_parser_count(self, golden_run):
        """SMS Parser should extract exactly the known number of messages."""
        gt = _get_gt(golden_run, "SMS Parser")
        actual = [a for a in golden_run["artifacts"] if a.artifact_type == "SMS"]
        assert len(actual) == gt["expected_count"], (
            f"SMS: expected {gt['expected_count']}, got {len(actual)}"
        )
    
    def test_sms_parser_content(self, golden_run):
        """SMS Parser should correctly extract message content and direction."""
        actual = [a for a in golden_run["artifacts"] if a.artifact_type == "SMS"]
        gt = _get_gt(golden_run, "SMS Parser")
        
        for sample in gt.get("sample_verification", []):
            matches = [a for a in actual 
                       if a.actor == sample["actor"]
                       and a.timestamp_utc == sample.get("timestamp_utc", a.timestamp_utc)]
            assert len(matches) > 0, f"No SMS found for actor={sample['actor']} ts={sample.get('timestamp_utc')}"
            
            if "details_contains" in sample:
                match = matches[0]
                for key, val in sample["details_contains"].items():
                    assert match.details.get(key) == val, (
                        f"SMS detail mismatch: {key}={match.details.get(key)}, expected={val}"
                    )
    
    def test_contacts_parser_count(self, golden_run):
        """Contacts Parser should extract exactly the known number of contacts."""
        gt = _get_gt(golden_run, "Contacts Parser")
        actual = [a for a in golden_run["artifacts"] if a.artifact_type == "CONTACT"]
        assert len(actual) == gt["expected_count"], (
            f"CONTACT: expected {gt['expected_count']}, got {len(actual)}"
        )
    
    def test_calllog_parser_count(self, golden_run):
        """Call Log Parser should extract exactly the known number of calls."""
        gt = _get_gt(golden_run, "Call Log Parser")
        actual = [a for a in golden_run["artifacts"] if a.artifact_type == "CALL_LOG"]
        assert len(actual) == gt["expected_count"], (
            f"CALL_LOG: expected {gt['expected_count']}, got {len(actual)}"
        )
    
    def test_calllog_parser_content(self, golden_run):
        """Call Log Parser should correctly classify call types and durations."""
        actual = [a for a in golden_run["artifacts"] if a.artifact_type == "CALL_LOG"]
        gt = _get_gt(golden_run, "Call Log Parser")
        
        for sample in gt.get("sample_verification", []):
            matches = [a for a in actual 
                       if a.actor == sample["actor"]
                       and a.timestamp_utc == sample.get("timestamp_utc", a.timestamp_utc)]
            assert len(matches) > 0, f"No CALL_LOG for actor={sample['actor']}"
            
            if "details_contains" in sample:
                match = matches[0]
                for key, val in sample["details_contains"].items():
                    assert match.details.get(key) == val, (
                        f"CALL_LOG detail mismatch: {key}={match.details.get(key)}, expected={val}"
                    )
    
    def test_chrome_parser_count(self, golden_run):
        """Chrome History Parser should extract exactly the known number of URLs."""
        gt = _get_gt(golden_run, "Chrome History Parser")
        actual = [a for a in golden_run["artifacts"] if a.artifact_type == "WEB_HISTORY"]
        assert len(actual) == gt["expected_count"], (
            f"WEB_HISTORY: expected {gt['expected_count']}, got {len(actual)}"
        )
    
    def test_installed_apps_count(self, golden_run):
        """Installed Apps Parser should extract exactly the known number of apps."""
        gt = _get_gt(golden_run, "Installed Apps Parser")
        actual = [a for a in golden_run["artifacts"] if a.artifact_type == "INSTALLED_APP"]
        assert len(actual) == gt["expected_count"], (
            f"INSTALLED_APP: expected {gt['expected_count']}, got {len(actual)}"
        )
    
    def test_accounts_parser_count(self, golden_run):
        """Accounts Parser should extract exactly the known number of accounts."""
        gt = _get_gt(golden_run, "Accounts Parser")
        actual = [a for a in golden_run["artifacts"] if a.artifact_type == "ACCOUNT"]
        assert len(actual) == gt["expected_count"], (
            f"ACCOUNT: expected {gt['expected_count']}, got {len(actual)}"
        )
    
    def test_whatsapp_detector(self, golden_run):
        """WhatsApp Detector should detect the msgstore.db presence."""
        gt = _get_gt(golden_run, "WhatsApp Detector")
        actual = [a for a in golden_run["artifacts"] if a.artifact_type == "ENCRYPTED_DB"]
        assert len(actual) == gt["expected_count"], (
            f"ENCRYPTED_DB: expected {gt['expected_count']}, got {len(actual)}"
        )
    
    def test_media_scanner_count(self, golden_run):
        """Media Scanner should detect exactly the known media files."""
        gt = _get_gt(golden_run, "Media Scanner")
        actual = [a for a in golden_run["artifacts"] if a.artifact_type == "MEDIA"]
        assert len(actual) == gt["expected_count"], (
            f"MEDIA: expected {gt['expected_count']}, got {len(actual)}"
        )
    
    def test_no_false_positives_telegram(self, golden_run):
        """No Telegram artifacts should be emitted (no Telegram DB present)."""
        actual = [a for a in golden_run["artifacts"] if a.artifact_type == "TELEGRAM_MSG"]
        assert len(actual) == 0, f"False positive: {len(actual)} TELEGRAM_MSG artifacts emitted"
    
    def test_text_file_not_media(self, golden_run):
        """Text files should not be detected as media."""
        actual = [a for a in golden_run["artifacts"] 
                  if a.artifact_type == "MEDIA" and "document.txt" in a.details.get("filename", "")]
        assert len(actual) == 0, "False positive: document.txt detected as MEDIA"
    
    def test_all_plugins_ran(self, golden_run):
        """All plugins should have run (at least attempted)."""
        runs = golden_run["plugin_runs"]
        # These plugins should have produced artifacts
        expected_parsers = {
            "SMS Parser", "Contacts Parser", "Call Log Parser",
            "Chrome History Parser", "Installed Apps Parser",
            "Accounts Parser", "WhatsApp Detector", "Media Scanner"
        }
        for parser in expected_parsers:
            assert parser in runs, f"Plugin {parser} did not run"
            assert runs[parser]["status"] in ("SUCCESS", "PARTIAL"), (
                f"Plugin {parser} status={runs[parser]['status']}"
            )
    
    def test_total_artifact_count(self, golden_run):
        """Total artifact count should match sum of expected counts."""
        gt = golden_run["ground_truth"]
        expected_total = sum(a["expected_count"] for a in gt["artifacts"])
        actual_total = len(golden_run["artifacts"])
        assert actual_total == expected_total, (
            f"Total artifacts: expected {expected_total}, got {actual_total}"
        )


def _get_gt(golden_run, parser_name):
    """Get ground truth entry for a specific parser."""
    for entry in golden_run["ground_truth"]["artifacts"]:
        if entry["parser"] == parser_name:
            return entry
    raise ValueError(f"No ground truth for parser: {parser_name}")
