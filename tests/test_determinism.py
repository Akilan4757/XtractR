"""
XtractR Determinism Test — Dual-Run Comparison (INV-002)

Executes the full pipeline twice on the golden dataset and asserts
byte-identical outputs, verifying deterministic transformation.
"""
import os
import sys
import json
import hashlib
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from core.database import CaseDatabase
from core.plugin_engine import PluginEngine
from core.vfs.directory import DirectoryVFS
from core.baseline import create_baseline
from core.timeline import TimelineEngine


GOLDEN_DIR = os.path.join(os.path.dirname(__file__), "golden", "data")


def _run_pipeline(tmp_dir, run_id):
    """Execute the full XtractR pipeline and return output hashes."""
    case_dir = os.path.join(tmp_dir, f"run_{run_id}")
    os.makedirs(case_dir, exist_ok=True)
    
    db_path = os.path.join(case_dir, "case.db")
    db = CaseDatabase(db_path)
    db.set_metadata("case_id", f"DET-TEST-{run_id}")
    
    vfs = DirectoryVFS(GOLDEN_DIR)
    create_baseline(vfs, db)
    
    plugin_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "plugins")
    engine = PluginEngine(plugin_dir, db)
    artifacts = engine.run_all(vfs)
    
    # Build timeline
    timeline = TimelineEngine(db, case_dir)
    timeline_path = timeline.build_timeline()
    
    # Collect output hashes
    outputs = {}
    
    # Hash timeline.json
    if os.path.exists(os.path.join(case_dir, "timeline.json")):
        with open(os.path.join(case_dir, "timeline.json"), "rb") as f:
            outputs["timeline.json"] = hashlib.sha256(f.read()).hexdigest()
    
    # Hash timeline.csv
    if os.path.exists(os.path.join(case_dir, "timeline.csv")):
        with open(os.path.join(case_dir, "timeline.csv"), "rb") as f:
            outputs["timeline.csv"] = hashlib.sha256(f.read()).hexdigest()
    
    # Collect derived artifacts from DB (sorted deterministically)
    cursor = db._conn.cursor()
    cursor.execute("""
        SELECT artifact_type, source_path, plugin_name, timestamp_utc, details, actor
        FROM derived_artifacts 
        ORDER BY timestamp_utc ASC, artifact_type ASC, source_path ASC, actor ASC
    """)
    rows = cursor.fetchall()
    artifacts_data = [
        {
            "type": r["artifact_type"],
            "source": r["source_path"],
            "plugin": r["plugin_name"],
            "ts": r["timestamp_utc"],
            "details": r["details"],
            "actor": r["actor"]
        }
        for r in rows
    ]
    artifacts_json = json.dumps(artifacts_data, sort_keys=True, separators=(',', ':')).encode()
    outputs["artifacts_canonical"] = hashlib.sha256(artifacts_json).hexdigest()
    outputs["artifact_count"] = len(artifacts_data)
    
    db.close()
    return outputs


class TestDeterminism:
    """Verify that identical inputs produce identical outputs (INV-002)."""
    
    def test_dual_run_timeline_identical(self, tmp_path):
        """Two runs on same golden dataset must produce identical timeline.json."""
        run1 = _run_pipeline(str(tmp_path), 1)
        run2 = _run_pipeline(str(tmp_path), 2)
        
        assert run1["timeline.json"] == run2["timeline.json"], (
            f"timeline.json differs: run1={run1['timeline.json'][:16]}... "
            f"run2={run2['timeline.json'][:16]}..."
        )
    
    def test_dual_run_csv_identical(self, tmp_path):
        """Two runs on same golden dataset must produce identical timeline.csv."""
        run1 = _run_pipeline(str(tmp_path), 1)
        run2 = _run_pipeline(str(tmp_path), 2)
        
        assert run1["timeline.csv"] == run2["timeline.csv"], (
            f"timeline.csv differs: run1={run1['timeline.csv'][:16]}... "
            f"run2={run2['timeline.csv'][:16]}..."
        )
    
    def test_dual_run_artifacts_identical(self, tmp_path):
        """Two runs must produce identical derived artifacts (canonical form)."""
        run1 = _run_pipeline(str(tmp_path), 1)
        run2 = _run_pipeline(str(tmp_path), 2)
        
        assert run1["artifact_count"] == run2["artifact_count"], (
            f"Artifact count differs: {run1['artifact_count']} vs {run2['artifact_count']}"
        )
        assert run1["artifacts_canonical"] == run2["artifacts_canonical"], (
            f"Artifacts differ: run1={run1['artifacts_canonical'][:16]}... "
            f"run2={run2['artifacts_canonical'][:16]}..."
        )
    
    def test_dual_run_artifact_count_nonzero(self, tmp_path):
        """Sanity check: runs should produce a non-trivial number of artifacts."""
        run1 = _run_pipeline(str(tmp_path), 1)
        assert run1["artifact_count"] > 0, "No artifacts produced — determinism test is vacuous"
