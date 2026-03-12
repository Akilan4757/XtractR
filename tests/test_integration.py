import pytest
import os
import shutil
import subprocess
import sys
import json
import zipfile

# Integration Test for Full Lifecycle

@pytest.fixture
def case_env(tmp_path):
    case_dir = tmp_path / "case_root"
    evidence_dir = tmp_path / "evidence_source"
    evidence_dir.mkdir()
    
    # Create dummy evidence
    (evidence_dir / "file1.txt").write_text("Hello World")
    (evidence_dir / "contacts2.db").write_text("SQLite format 3...") # Fake DB header
    
    return str(case_dir), str(evidence_dir)

def test_full_lifecycle_cli(case_env):
    case_dir, evidence_dir = case_env
    # We call main.py directly via subprocess to test CLI argument parsing too
    
    main_py = os.path.abspath("main.py")
    env = os.environ.copy()
    env["PYTHONPATH"] = os.getcwd()
    
    def run_cmd(args):
        cmd = [sys.executable, main_py] + args
        res = subprocess.run(cmd, env=env, capture_output=True, text=True)
        assert res.returncode == 0, f"Command failed: {args}\nStderr: {res.stderr}"
        return res

    # 1. Init
    run_cmd(["init", "--case-id", "TEST_CASE_001", "--output", case_dir, "--investigator-name", "Test Investigator"])
    assert os.path.exists(os.path.join(case_dir, "case.db"))
    assert os.path.exists(os.path.join(case_dir, "keys", "investigator.pem"))

    # 2. Ingest
    run_cmd(["ingest", "--case-dir", case_dir, "--source", evidence_dir])
    
    # 3. Scan
    run_cmd(["scan", "--case-dir", case_dir])
    
    # 4. Plugins
    run_cmd(["run-plugins", "--case-dir", case_dir])
    
    # 5. Process (Timeline)
    run_cmd(["process", "--case-dir", case_dir])
    assert os.path.exists(os.path.join(case_dir, "timeline.json"))
    
    # 6. Report
    run_cmd(["report", "--case-dir", case_dir])
    assert os.path.exists(os.path.join(case_dir, "report.html"))

    # 7. Export
    run_cmd(["export", "--case-dir", case_dir])
    export_dir = os.path.join(case_dir, "exports")
    bundles = os.listdir(export_dir)
    assert len(bundles) == 1
    bundle_path = os.path.join(export_dir, bundles[0])
    
    # 8. Unzip & Verify (using xtractr_verify.py)
    verify_py = os.path.abspath("xtractr_verify.py")
    extract_path = os.path.join(case_dir, "check_verify")
    with zipfile.ZipFile(bundle_path, 'r') as z:
        z.extractall(extract_path)
        
    pub_key = os.path.join(extract_path, "investigator.pub")
    
    # Run Verify
    cmd = [sys.executable, verify_py, "--case-dir", extract_path, "--pub-key", pub_key]
    res = subprocess.run(cmd, env=env, capture_output=True, text=True)
    assert res.returncode == 0
    assert "Ledger Integrity: VALID" in res.stdout
    assert "Manifest Signature: VALID" in res.stdout
    assert "Signature VALID: case.db" in res.stdout
    assert "System Root: VALID" in res.stdout
    assert "--- VERIFICATION SUCCESSFUL ---" in res.stdout

