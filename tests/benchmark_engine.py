"""
XtractR Benchmark Metrics Engine

Runs all parsers against the golden dataset, collects metrics,
and produces a structured validation_report.json.

Usage:
    python -m tests.benchmark_engine [--output-dir <dir>]

Report contains:
  - Per-parser precision/recall/F1
  - Per-parser latency (ms)
  - Global totals
  - Ground truth comparison (expected vs actual counts)
"""
import os
import sys
import json
import time
import tempfile
import argparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.database import CaseDatabase
from core.ingest import get_vfs
from core.baseline import create_baseline
from core.plugin_engine import PluginEngine
from core.integrity import canonical_json


def load_ground_truth():
    gt_path = os.path.join(os.path.dirname(__file__), "golden", "ground_truth.json")
    with open(gt_path, "r") as f:
        return json.load(f)


def run_benchmark(output_dir=None):
    golden_dir = os.path.join(os.path.dirname(__file__), "golden", "data")
    if not os.path.isdir(golden_dir):
        print("ERROR: Golden dataset not found. Run generate_golden.py first.")
        sys.exit(1)

    gt = load_ground_truth()

    # Create temp case dir
    tmpdir = tempfile.mkdtemp(prefix="benchmark_")
    case_dir = os.path.join(tmpdir, "case")
    os.makedirs(case_dir, exist_ok=True)

    db_path = os.path.join(case_dir, "case.db")
    db = CaseDatabase(db_path)
    db.set_metadata("case_id", "BENCHMARK-001")

    # Baseline
    vfs = get_vfs(golden_dir)
    create_baseline(vfs, db)

    # Run plugins and measure time
    plugin_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "plugins"
    )

    start_total = time.time()
    engine = PluginEngine(plugin_dir, db)
    engine.run_all(vfs)
    total_ms = (time.time() - start_total) * 1000

    # Collect results
    cursor = db._conn.cursor()
    cursor.execute("""
        SELECT plugin_name, artifact_type, COUNT(*) as cnt
        FROM derived_artifacts
        GROUP BY plugin_name, artifact_type
        ORDER BY plugin_name ASC
    """)
    actual_counts = {}
    for row in cursor.fetchall():
        key = row[0]  # plugin_name
        actual_counts[key] = actual_counts.get(key, 0) + row[2]

    # Build per-parser report
    parser_results = []
    total_expected = 0
    total_actual = 0
    total_tp = 0

    for gt_entry in gt["artifacts"]:
        parser_name = gt_entry["parser"]
        expected = gt_entry["expected_count"]
        actual = actual_counts.get(parser_name, 0)

        # True positives = min(expected, actual)
        tp = min(expected, actual)
        fp = max(0, actual - expected)
        fn = max(0, expected - actual)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

        parser_results.append({
            "parser": parser_name,
            "artifact_type": gt_entry["artifact_type"],
            "expected_count": expected,
            "actual_count": actual,
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
        })

        total_expected += expected
        total_actual += actual
        total_tp += tp

    # Global metrics
    global_precision = total_tp / total_actual if total_actual > 0 else 0.0
    global_recall    = total_tp / total_expected if total_expected > 0 else 0.0
    global_f1        = (2 * global_precision * global_recall /
                        (global_precision + global_recall)
                        if (global_precision + global_recall) > 0 else 0.0)

    report = {
        "benchmark_version": "2.0.0",
        "dataset_version": gt.get("dataset_version", "unknown"),
        "total_expected_artifacts": total_expected,
        "total_actual_artifacts": total_actual,
        "total_true_positives": total_tp,
        "global_precision": round(global_precision, 4),
        "global_recall": round(global_recall, 4),
        "global_f1_score": round(global_f1, 4),
        "total_execution_ms": round(total_ms, 2),
        "parser_results": parser_results,
    }

    db.close()

    # Write report
    out_dir = output_dir or os.path.dirname(__file__)
    report_path = os.path.join(out_dir, "validation_report.json")
    with open(report_path, "wb") as f:
        f.write(canonical_json(report))

    # Also pretty-print
    report_pretty = os.path.join(out_dir, "validation_report_pretty.json")
    with open(report_pretty, "w") as f:
        json.dump(report, f, indent=2, sort_keys=True)

    # Cleanup
    import shutil
    shutil.rmtree(tmpdir, ignore_errors=True)

    return report, report_path


def print_report(report):
    print("\n" + "="*60)
    print("XtractR Validation Report")
    print("="*60)
    print(f"  Dataset Version:     {report['dataset_version']}")
    print(f"  Total Expected:      {report['total_expected_artifacts']}")
    print(f"  Total Actual:        {report['total_actual_artifacts']}")
    print(f"  Global Precision:    {report['global_precision']:.4f}")
    print(f"  Global Recall:       {report['global_recall']:.4f}")
    print(f"  Global F1:           {report['global_f1_score']:.4f}")
    print(f"  Execution Time:      {report['total_execution_ms']:.2f} ms")
    print("-"*60)

    for p in report["parser_results"]:
        status = "✓" if p["expected_count"] == p["actual_count"] else "✗"
        print(f"  {status} {p['parser']:<25} "
              f"exp={p['expected_count']:>4} act={p['actual_count']:>4} "
              f"P={p['precision']:.2f} R={p['recall']:.2f} F1={p['f1_score']:.2f}")

    print("="*60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="XtractR Benchmark Engine")
    parser.add_argument("--output-dir", help="Directory for validation_report.json")
    args = parser.parse_args()

    report, path = run_benchmark(args.output_dir)
    print_report(report)
    print(f"\nReport saved to: {path}")
