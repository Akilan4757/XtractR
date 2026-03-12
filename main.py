#!/usr/bin/env python3
import argparse
import sys
import os
import logging
from core.database import CaseDatabase
from core.crypto import IdentityManager
from core.ingest import get_vfs
from core.baseline import create_baseline
from core.plugin_engine import PluginEngine
from core.timeline import TimelineEngine
from core.correlation import CorrelationEngine
from core.reporting import generate_report

from core.export import ExportManager
from core.environment import log_environment

# Setup Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("xtractr")

def main():
    parser = argparse.ArgumentParser(description="XtractR Forensic Core")
    subparsers = parser.add_subparsers(dest="command")

    # init
    cmd_init = subparsers.add_parser("init", help="Initialize a new case")
    cmd_init.add_argument("--case-id", required=True)
    cmd_init.add_argument("--output", required=True, help="Case Directory")
    cmd_init.add_argument("--investigator-name", required=True, help="Name of the investigating officer (mandatory)")
    cmd_init.add_argument("--passphrase", help="Key passphrase (prompted if not provided)")

    # ingest
    cmd_ingest = subparsers.add_parser("ingest", help="Ingest evidence source")
    cmd_ingest.add_argument("--case-dir", required=True)
    cmd_ingest.add_argument("--source", required=True, help="Input file/dir")
    cmd_ingest.add_argument("--passphrase", help="Key passphrase")

    # scan (baseline)
    cmd_scan = subparsers.add_parser("scan", help="Create integrity baseline")
    cmd_scan.add_argument("--case-dir", required=True)
    cmd_scan.add_argument("--passphrase", help="Key passphrase")

    # plugins
    cmd_plugins = subparsers.add_parser("run-plugins", help="Execute plugins")
    cmd_plugins.add_argument("--case-dir", required=True)
    cmd_plugins.add_argument("--passphrase", help="Key passphrase")

    # processing
    cmd_proc = subparsers.add_parser("process", help="Run Timeline & Correlation")
    cmd_proc.add_argument("--case-dir", required=True)
    cmd_proc.add_argument("--passphrase", help="Key passphrase")
    
    # report
    cmd_report = subparsers.add_parser("report", help="Generate Report & Certs")
    cmd_report.add_argument("--case-dir", required=True)
    cmd_report.add_argument("--passphrase", help="Key passphrase")
    
    # export
    cmd_export = subparsers.add_parser("export", help="Create Export Bundle")
    cmd_export.add_argument("--case-dir", required=True)
    cmd_export.add_argument("--passphrase", help="Key passphrase")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Resolve passphrase
    passphrase = getattr(args, 'passphrase', None)
    passphrase_bytes = passphrase.encode("utf-8") if passphrase else None

    # Common Init
    if args.command == "init":
        if os.path.exists(args.output):
            logger.error("Output directory already exists")
            sys.exit(1)
        os.makedirs(args.output)
        
        # Identity
        id_mgr = IdentityManager(os.path.join(args.output, "keys"))
        id_mgr.load_or_generate_keys(passphrase_bytes)
        
        # DB
        db = CaseDatabase(os.path.join(args.output, "case.db"))
        db.set_metadata("case_id", args.case_id)
        db.set_metadata("investigator_name", args.investigator_name)
        db.log_event("CASE_INIT", f"Initialized Case {args.case_id} by {args.investigator_name}", actor="USER")

        # Measured Boot: Log tool environment hash
        log_environment(db)

        db.close()
        logger.info(f"Case {args.case_id} initialized at {args.output} (Investigator: {args.investigator_name})")
        return

    # Load Context for other commands
    if not os.path.exists(args.case_dir):
        logger.error("Case directory not found")
        sys.exit(1)
        
    db_path = os.path.join(args.case_dir, "case.db")
    db = CaseDatabase(db_path)
    id_mgr = IdentityManager(os.path.join(args.case_dir, "keys"))
    if not id_mgr.load_or_generate_keys(passphrase_bytes):
        logger.error("Identity keys missing/corrupt or wrong passphrase")
        sys.exit(1)

    try:
        if args.command == "ingest":
            # Just verify source exists and log it
            if not os.path.exists(args.source):
                logger.error("Source not found")
                sys.exit(1)
            
            db.set_metadata("source_path", os.path.abspath(args.source))
            db.log_event("EVIDENCE_ACQUIRED", f"Source: {args.source}")
            logger.info("Evidence Linked.")

        elif args.command == "scan":
            src = db.get_metadata("source_path")
            if not src:
                logger.error("No evidence linked. Run ingest first.")
                sys.exit(1)
                
            vfs = get_vfs(src)
            create_baseline(vfs, db)

        elif args.command == "run-plugins":
            src = db.get_metadata("source_path")
            if not src: sys.exit(1)
            vfs = get_vfs(src)
            
            engine = PluginEngine("plugins", db)
            engine.run_all(vfs)

        elif args.command == "process":
            # Timeline
            tl_engine = TimelineEngine(db, args.case_dir)
            tl_engine.build_timeline()
            
            # Correlation
            corr_engine = CorrelationEngine(db)
            corr_engine.run_correlations()
            
            db.log_event("PROCESSING_COMPLETE", "Timeline and Correlation finished")

        elif args.command == "report":
            # HTML Report
            generate_report(db, args.case_dir)
            
            db.log_event("REPORT_GENERATED", "HTML Report created")

        elif args.command == "export":
            exporter = ExportManager(db, id_mgr, args.case_dir)
            path = exporter.create_bundle()
            # NOTE: Do NOT call db.log_event() after create_bundle() — any custody
            # event written after the seal is computed corrupts the sealed log_root.
            logger.info(f"Export Bundle Ready: {path}")

    except Exception as e:
        logger.critical(f"Command Failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        db.close()

if __name__ == "__main__":
    main()
