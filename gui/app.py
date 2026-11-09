"""
XtractR GUI — Flask Application
Local forensic workstation web interface for XtractR pipeline operations.
"""
import os
import json
import logging
import re
import shutil
import tempfile
from werkzeug.exceptions import RequestEntityTooLarge
from flask import Flask, render_template, request, jsonify, Response, send_file

from .case_manager import CaseManager

logger = logging.getLogger("xtractr.gui")

# Default cases root — configurable via environment variable
DEFAULT_CASES_ROOT = os.path.join(os.path.expanduser("~"), "XtractR-Cases")
try:
    MAX_VERIFY_UPLOAD_BYTES = max(1, int(os.environ.get("XTRACTR_MAX_VERIFY_UPLOAD_BYTES", 8 * 1024**3)))
except ValueError:
    MAX_VERIFY_UPLOAD_BYTES = 8 * 1024**3


def create_app(cases_root: str = None) -> Flask:
    app = Flask(__name__,
                template_folder=os.path.join(os.path.dirname(__file__), "templates"),
                static_folder=os.path.join(os.path.dirname(__file__), "static"))
    # Leave room for multipart boundaries and the fingerprint fields around the file.
    app.config["MAX_CONTENT_LENGTH"] = MAX_VERIFY_UPLOAD_BYTES + 1024**2

    @app.errorhandler(RequestEntityTooLarge)
    def upload_too_large(_error):
        return jsonify({"success": False,
                        "error": f"Bundle exceeds the {MAX_VERIFY_UPLOAD_BYTES / (1024**3):g} GiB upload limit."}), 413

    root = cases_root or os.environ.get("XTRACTR_CASES_ROOT", DEFAULT_CASES_ROOT)
    mgr = CaseManager(root)

    # ── Pages ────────────────────────────────────────────────────

    @app.route("/")
    def index():
        return render_template("index.html", cases_root=root,
                               max_verify_upload_bytes=MAX_VERIFY_UPLOAD_BYTES)

    # ── Case API ─────────────────────────────────────────────────

    @app.route("/api/cases", methods=["GET"])
    def api_list_cases():
        cases = mgr.list_cases()
        return jsonify({"cases": cases, "cases_root": root})

    @app.route("/api/case/new", methods=["POST"])
    def api_new_case():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({"success": False, "error": "Expected case details as a JSON object"}), 400
        case_id = data.get("case_id", "")
        investigator = data.get("investigator_name", "")
        passphrase = data.get("passphrase", "")
        if not all(isinstance(value, str) for value in (case_id, investigator, passphrase)):
            return jsonify({"success": False, "error": "Case details must be text"}), 400
        case_id = case_id.strip()
        investigator = investigator.strip()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}", case_id) or ".." in case_id:
            return jsonify({"success": False, "error": "Use 1-80 letters, numbers, dots, underscores, or hyphens for the case ID"}), 400
        if not investigator or len(investigator) > 120:
            return jsonify({"success": False, "error": "Investigator name is required and must be at most 120 characters"}), 400
        if len(passphrase) < 12:
            return jsonify({"success": False, "error": "Use a signing-key passphrase of at least 12 characters"}), 400

        result = mgr.init_case(case_id, investigator, passphrase)
        return jsonify(result)

    @app.route("/api/case/<case_id>/info", methods=["GET"])
    def api_case_info(case_id):
        info = mgr.get_case(case_id)
        if not info:
            return jsonify({"success": False, "error": "Case not found"}), 404
        return jsonify({"success": True, **info.to_dict()})

    @app.route("/api/case/<case_id>/stats", methods=["GET"])
    def api_case_stats(case_id):
        return jsonify(mgr.get_artifact_stats(case_id))

    # ── Pipeline operations (synchronous for simplicity, SSE for long ones) ──

    @app.route("/api/case/<case_id>/ingest", methods=["POST"])
    def api_ingest(case_id):
        data = request.get_json()
        source = data.get("source_path", "").strip()
        passphrase = data.get("passphrase", "")
        if not source:
            return jsonify({"success": False, "error": "source_path required"}), 400
        result = mgr.ingest_evidence(case_id, source, passphrase)
        return jsonify(result)

    @app.route("/api/case/<case_id>/scan", methods=["POST"])
    def api_scan(case_id):
        data = request.get_json() or {}
        passphrase = data.get("passphrase", "")
        task_id = mgr.start_task(case_id, "scan", mgr.run_scan, case_id, passphrase)
        return jsonify({"success": True, "task_id": task_id})

    @app.route("/api/case/<case_id>/run-plugins", methods=["POST"])
    def api_run_plugins(case_id):
        data = request.get_json() or {}
        passphrase = data.get("passphrase", "")
        task_id = mgr.start_task(case_id, "plugins", mgr.run_plugins, case_id, passphrase)
        return jsonify({"success": True, "task_id": task_id})

    @app.route("/api/case/<case_id>/process", methods=["POST"])
    def api_process(case_id):
        data = request.get_json() or {}
        passphrase = data.get("passphrase", "")
        task_id = mgr.start_task(case_id, "process", mgr.run_processing, case_id, passphrase)
        return jsonify({"success": True, "task_id": task_id})

    @app.route("/api/case/<case_id>/report", methods=["POST"])
    def api_report(case_id):
        data = request.get_json() or {}
        passphrase = data.get("passphrase", "")
        task_id = mgr.start_task(case_id, "report", mgr.generate_report, case_id, passphrase)
        return jsonify({"success": True, "task_id": task_id})

    @app.route("/api/case/<case_id>/export", methods=["POST"])
    def api_export(case_id):
        data = request.get_json() or {}
        passphrase = data.get("passphrase", "")
        include_evidence = bool(data.get("include_evidence", True))
        task_id = mgr.start_task(case_id, "export", mgr.create_export, case_id, passphrase, include_evidence)
        return jsonify({"success": True, "task_id": task_id})

    # ── SSE Task streaming ───────────────────────────────────────

    @app.route("/api/task/<task_id>/stream")
    def api_task_stream(task_id):
        def generate():
            for msg in mgr.get_task_messages(task_id):
                yield f"data: {json.dumps(msg)}\n\n"
        return Response(generate(), mimetype="text/event-stream",
                        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    @app.route("/api/case/<case_id>/verify", methods=["POST"])
    def api_verify(case_id):
        data = request.get_json(silent=True) or {}
        result = mgr.verify_case(
            case_id,
            expected_fingerprint=data.get("expected_fingerprint", ""),
            check_evidence=data.get("check_evidence", True),
        )
        return jsonify(result)

    @app.route("/api/verify-bundle", methods=["POST"])
    def api_verify_bundle():
        uploaded = request.files.get("bundle")
        if not uploaded or not uploaded.filename:
            return jsonify({"success": False, "error": "Choose an XtractR ZIP bundle first."}), 400
        original_name = os.path.basename(uploaded.filename.replace("\\", "/"))
        if not original_name.lower().endswith(".zip"):
            return jsonify({"success": False, "error": "Received bundles must be ZIP files."}), 400

        upload_dir = tempfile.mkdtemp(prefix="xtractr-recipient-verify-")
        bundle_path = os.path.join(upload_dir, "received-bundle.zip")
        try:
            uploaded.save(bundle_path)
            expected_fingerprint = request.form.get("expected_fingerprint", "").strip()
            check_evidence = request.form.get("check_evidence", "true").lower() == "true"

            def verify_uploaded(progress_cb=None):
                try:
                    import xtractr_verify
                    result = xtractr_verify.verify_bundle_archive(
                        bundle_path,
                        expected_fingerprint=expected_fingerprint or None,
                        check_evidence=check_evidence,
                        progress_cb=progress_cb,
                    )
                    result["bundle_name"] = original_name
                    return result
                finally:
                    shutil.rmtree(upload_dir, ignore_errors=True)

            task_id = mgr.start_task("received", "verify_bundle", verify_uploaded)
            return jsonify({"success": True, "task_id": task_id}), 202
        except Exception as exc:
            shutil.rmtree(upload_dir, ignore_errors=True)
            logger.exception("Could not start received-bundle verification")
            return jsonify({"success": False, "error": str(exc)}), 500

    @app.route("/api/case/<case_id>/evidence-readme", methods=["GET"])
    def api_evidence_readme(case_id):
        info = mgr.get_case(case_id)
        if not info:
            return jsonify({"success": False, "error": "Case not found"}), 404
        readme_path = os.path.join(info.case_dir, "README_EVIDENCE.md")
        if not os.path.isfile(readme_path):
            return jsonify({"success": False, "error": "Export the case to generate the evidence hash README"}), 404
        return send_file(readme_path, mimetype="text/markdown", as_attachment=True,
                         download_name="README_EVIDENCE.md")

    @app.route("/api/case/<case_id>/latest-export", methods=["GET"])
    def api_latest_export(case_id):
        info = mgr.get_case(case_id)
        if not info:
            return jsonify({"success": False, "error": "Case not found"}), 404
        exports_dir = os.path.join(info.case_dir, "exports")
        bundles = [os.path.join(exports_dir, name) for name in os.listdir(exports_dir)
                   if name.lower().endswith(".zip")] if os.path.isdir(exports_dir) else []
        if not bundles:
            return jsonify({"success": False, "error": "No exported bundle is available"}), 404
        latest = max(bundles, key=os.path.getmtime)
        return send_file(latest, mimetype="application/zip", as_attachment=True,
                         download_name=os.path.basename(latest))

    # ── Data endpoints ───────────────────────────────────────────

    @app.route("/api/case/<case_id>/artifacts", methods=["GET"])
    def api_artifacts(case_id):
        page = int(request.args.get("page", 1))
        per_page = int(request.args.get("per_page", 50))
        artifact_type = request.args.get("type")
        actor = request.args.get("actor")
        search = request.args.get("search")
        return jsonify(mgr.get_artifacts(case_id, artifact_type, actor, search, page, per_page))

    @app.route("/api/case/<case_id>/timeline", methods=["GET"])
    def api_timeline(case_id):
        return jsonify(mgr.get_timeline(case_id))

    @app.route("/api/case/<case_id>/custody-log", methods=["GET"])
    def api_custody_log(case_id):
        return jsonify(mgr.get_custody_log(case_id))

    @app.route("/api/case/<case_id>/report-file", methods=["GET"])
    def api_report_file(case_id):
        info = mgr.get_case(case_id)
        if not info:
            return jsonify({"error": "Case not found"}), 404
        report_path = os.path.join(info.case_dir, "report.html")
        if not os.path.exists(report_path):
            return jsonify({"error": "Report not generated yet"}), 404
        return send_file(report_path, mimetype="text/html")

    return app
