"""
XtractR Failure Taxonomy — Strict Classification

Every failure in the system MUST map to exactly one FailureCode.
Each code has a defined exit status and severity.
All failures are logged, hashed into the execution log Merkle tree,
and appear in validation_report.json.
"""
import enum
import sys
import logging

logger = logging.getLogger("xtractr.failure")


class Severity(enum.IntEnum):
    """Failure severity levels."""
    INFO = 0       # Informational, no impact
    WARNING = 1    # Degraded but functional
    ERROR = 2      # Operation failed
    CRITICAL = 3   # System integrity compromised — immediate halt


class FailureCode(enum.Enum):
    """
    Strict failure classification.
    Tuple: (code_string, exit_status, severity)
    """
    VALIDATION_ERROR           = ("VALIDATION_ERROR",           1, Severity.ERROR)
    RESOURCE_LIMIT             = ("RESOURCE_LIMIT",             2, Severity.ERROR)
    TIMEOUT                    = ("TIMEOUT",                    3, Severity.ERROR)
    PARSER_EXCEPTION           = ("PARSER_EXCEPTION",           4, Severity.ERROR)
    SCHEMA_DRIFT               = ("SCHEMA_DRIFT",              5, Severity.WARNING)
    CORRUPTED_INPUT            = ("CORRUPTED_INPUT",            6, Severity.ERROR)
    SIGNATURE_INVALID          = ("SIGNATURE_INVALID",         11, Severity.CRITICAL)
    MERKLE_MISMATCH            = ("MERKLE_MISMATCH",           10, Severity.CRITICAL)
    VERSION_DRIFT              = ("VERSION_DRIFT",             13, Severity.WARNING)
    ENVIRONMENT_NONDETERMINISM = ("ENVIRONMENT_NONDETERMINISM", 78, Severity.CRITICAL)

    @property
    def code(self) -> str:
        return self.value[0]

    @property
    def exit_status(self) -> int:
        return self.value[1]

    @property
    def severity(self) -> Severity:
        return self.value[2]

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "exit_status": self.exit_status,
            "severity": self.severity.name,
        }


def fail_hard(failure: FailureCode, detail: str = "") -> None:
    """
    Log a critical failure and terminate the process immediately.
    Used for integrity-compromising conditions that cannot be recovered.
    """
    msg = f"FATAL [{failure.code}]: {detail}"
    logger.critical(msg)
    print(msg, file=sys.stderr)
    sys.exit(failure.exit_status)


def classify_exception(exc: Exception) -> FailureCode:
    """Map a Python exception to the appropriate FailureCode."""
    if isinstance(exc, MemoryError):
        return FailureCode.RESOURCE_LIMIT
    if isinstance(exc, TimeoutError):
        return FailureCode.TIMEOUT
    if isinstance(exc, (ValueError, TypeError, KeyError)):
        return FailureCode.VALIDATION_ERROR
    if isinstance(exc, UnicodeDecodeError):
        return FailureCode.CORRUPTED_INPUT
    if isinstance(exc, OSError):
        return FailureCode.CORRUPTED_INPUT
    return FailureCode.PARSER_EXCEPTION
