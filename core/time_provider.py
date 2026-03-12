"""
XtractR Time Provider — Centralized, Deterministic Time Source

Rules:
  - No direct datetime.now() usage anywhere else in the codebase.
  - All timestamps are UTC epoch milliseconds (integer).
  - Execution timestamp frozen at init.
  - Plugins cannot access system clock (enforced by process isolation).
  - Runtime assertion: TZ=UTC, LC_ALL=C, PYTHONHASHSEED=0.
  - Immediate sys.exit(78) on violation.
"""
import os
import sys
import time
import logging

logger = logging.getLogger("xtractr.time")

# Required environment for deterministic execution
_REQUIRED_ENV = {
    "PYTHONHASHSEED": "0",
    "LC_ALL": "C",
    "TZ": "UTC",
}


def validate_environment() -> None:
    """
    Validate that the runtime environment is configured for deterministic
    execution. Exits immediately with code 78 (EX_CONFIG) if any variable
    is missing or incorrect.
    """
    violations = []
    for var, expected in sorted(_REQUIRED_ENV.items()):
        actual = os.environ.get(var)
        if actual != expected:
            violations.append(
                f"  {var}: expected='{expected}', actual='{actual}'"
            )

    if violations:
        msg = (
            "FATAL [ENVIRONMENT_NONDETERMINISM]: "
            "Runtime environment not configured for deterministic execution.\n"
            + "\n".join(violations)
        )
        logger.critical(msg)
        print(msg, file=sys.stderr)
        sys.exit(78)


class TimeProvider:
    """
    Singleton time source for XtractR.

    Usage:
        tp = TimeProvider.get()
        ts = tp.now_ms()
        exec_ts = tp.execution_timestamp
    """
    _instance = None

    def __init__(self):
        self._execution_timestamp = int(time.time() * 1000)

    @classmethod
    def get(cls) -> "TimeProvider":
        """Return the singleton instance, creating it if needed."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Reset singleton (for testing only)."""
        cls._instance = None

    @property
    def execution_timestamp(self) -> int:
        """Frozen timestamp from when execution started (UTC ms)."""
        return self._execution_timestamp

    @staticmethod
    def now_ms() -> int:
        """Current UTC time in epoch milliseconds."""
        return int(time.time() * 1000)
