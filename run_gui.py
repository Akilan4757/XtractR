"""
XtractR GUI — Entry Point
Launch: python run_gui.py
"""
import os
import sys

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gui.app import create_app

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="XtractR Forensic Dashboard")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5000, help="Port (default: 5000)")
    parser.add_argument("--cases-root", default=None,
                        help="Root directory for cases (default: ~/XtractR-Cases)")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")

    args = parser.parse_args()

    app = create_app(cases_root=args.cases_root)

    print(f"""
    ================================================
    |        XtractR Forensic Dashboard            |
    |                                              |
    |   http://{args.host}:{args.port}                   |
    |                                              |
    ================================================
    """)

    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)
