"""
XtractR Centralized Logging Module (Issue #18)

Provides structured logging with:
- Colored console output for investigator readability
- JSON lines file handler for machine-parseable audit trails
- Configurable verbosity levels
"""

import logging
import json
import sys
from datetime import datetime


class ColorFormatter(logging.Formatter):
    """Console formatter with ANSI colors for forensic readability."""

    COLORS = {
        logging.DEBUG: "\033[90m",      # Gray
        logging.INFO: "\033[96m",       # Cyan
        logging.WARNING: "\033[93m",    # Yellow
        logging.ERROR: "\033[91m",      # Red
        logging.CRITICAL: "\033[91m\033[1m",  # Bold Red
    }
    RESET = "\033[0m"

    def format(self, record):
        color = self.COLORS.get(record.levelno, self.RESET)
        levelname = f"{color}{record.levelname:<8}{self.RESET}"
        msg = super().format(record)
        return msg.replace(record.levelname, levelname, 1)


class JsonLineHandler(logging.FileHandler):
    """File handler that writes structured JSON lines for audit trails."""

    def emit(self, record):
        try:
            entry = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
            }
            if record.exc_info and record.exc_info[0]:
                entry["exception"] = self.format(record).split("\n")[-1]
            record.msg = json.dumps(entry)
            record.args = None
            super().emit(record)
        except Exception:
            self.handleError(record)


def setup_logging(verbosity="INFO", log_file=None):
    """
    Configure the XtractR logging system.

    Args:
        verbosity: Log level string (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional path to JSON lines log file
    """
    root_logger = logging.getLogger("xtractr")
    root_logger.setLevel(getattr(logging, verbosity.upper(), logging.INFO))

    # Clear existing handlers to avoid duplicates on re-init
    root_logger.handlers.clear()

    # Console handler with colors
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(ColorFormatter("%(levelname)s %(name)s :: %(message)s"))
    root_logger.addHandler(console)

    # Optional JSON file handler
    if log_file:
        file_handler = JsonLineHandler(log_file)
        file_handler.setFormatter(logging.Formatter("%(message)s"))
        root_logger.addHandler(file_handler)

    return root_logger
