"""
XtractR Artifact Validator (INV-004, INV-007)
Runtime enforcement of artifact schema completeness and semantic rules.
"""
import re
import json
import logging
from typing import List, Tuple, Optional
from .plugin_interface import Artifact

logger = logging.getLogger("xtractr.validator")

# Semantic version pattern
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+.*$")

# Valid artifact types (extensible via registration)
VALID_ARTIFACT_TYPES = {
    "SMS", "CALL_LOG", "CONTACT", "BROWSER_HISTORY",
    "INSTALLED_APP", "MEDIA_FILE", "WHATSAPP_MSG",
    "WHATSAPP_PRESENCE", "ACCOUNT", "LOCATION",
    "NOTIFICATION", "SYSTEM_EVENT", "UNKNOWN",
    # Inferred variants
    "SMS_INFERRED", "CALL_LOG_INFERRED", "CONTACT_INFERRED",
    "BROWSER_HISTORY_INFERRED", "MEDIA_FILE_INFERRED",
}

# Plausible timestamp range: 2007-01-01 to 2030-01-01 (in ms)
TS_MIN = 1167609600000   # 2007-01-01T00:00:00Z
TS_MAX = 1893456000000   # 2030-01-01T00:00:00Z


def validate_artifact(art: Artifact) -> Tuple[bool, Optional[str]]:
    """
    Validate a single artifact against schema and semantic rules.
    Returns (is_valid, error_message).
    
    INV-004: All required fields must be non-null and non-empty.
    INV-007: Confidence must be consistent with artifact type.
    """
    
    if not art.artifact_id or not isinstance(art.artifact_id, str):
        return False, "artifact_id is missing or not a string"
    
    if not art.artifact_type or not isinstance(art.artifact_type, str):
        return False, "artifact_type is missing or not a string"
    
    if art.artifact_type not in VALID_ARTIFACT_TYPES:
        logger.warning(f"Unknown artifact_type '{art.artifact_type}' — allowing but flagging")
    
    if not art.source_path or not isinstance(art.source_path, str):
        return False, "source_path is missing or not a string"
    
    if not isinstance(art.timestamp_utc, int) or art.timestamp_utc < 0:
        return False, f"timestamp_utc invalid: {art.timestamp_utc}"
    
    # Timestamp sanity check (SEM-004)
    if art.timestamp_utc > 0 and (art.timestamp_utc < TS_MIN or art.timestamp_utc > TS_MAX):
        logger.warning(f"timestamp_utc {art.timestamp_utc} outside plausible range for {art.artifact_id}")
    
    if not art.parser_name or not isinstance(art.parser_name, str):
        return False, "parser_name is missing or not a string"
    
    if not art.parser_version or not isinstance(art.parser_version, str):
        return False, "parser_version is missing or not a string"
    
    if not art.actor or not isinstance(art.actor, str):
        return False, "actor is missing or not a string"
    
    if not isinstance(art.details, dict):
        return False, f"details must be a dict, got {type(art.details).__name__}"
    
    
    if not isinstance(art.confidence, (int, float)):
        return False, f"confidence must be numeric, got {type(art.confidence).__name__}"
    
    if not (0.0 <= art.confidence <= 1.0):
        return False, f"confidence must be 0.0-1.0, got {art.confidence}"
    
    # Zero-speculation rule: inferred artifacts must not have confidence == 1.0
    if art.artifact_type.endswith("_INFERRED") and art.confidence >= 1.0:
        return False, "INFERRED artifacts must have confidence < 1.0"
    
    try:
        details_size = len(json.dumps(art.details, default=str))
        if details_size > 10_000_000:  # 10 MB
            return False, f"details too large: {details_size} bytes"
    except (TypeError, ValueError) as e:
        return False, f"details not JSON-serializable: {e}"
    
    return True, None


def validate_artifact_batch(artifacts: List[Artifact]) -> Tuple[List[Artifact], List[Tuple[Artifact, str]]]:
    """
    Validate a batch of artifacts.
    Returns (valid_artifacts, [(invalid_artifact, reason), ...]).
    """
    valid = []
    invalid = []
    
    for art in artifacts:
        is_valid, reason = validate_artifact(art)
        if is_valid:
            valid.append(art)
        else:
            invalid.append((art, reason))
            logger.error(f"Artifact validation failed [{art.artifact_id}]: {reason}")
    
    return valid, invalid
