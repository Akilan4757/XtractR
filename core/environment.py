"""
XtractR Execution Environment Verification — Measured Boot

Computes a Merkle root of all Python source files in the tool's
core/, orchestrator/, and plugins/ directories. This hash is logged
as the first custody event, proving the exact tool state used for
the forensic acquisition.
"""
import os
import hashlib
import logging
from typing import List
from .integrity import compute_merkle_root

logger = logging.getLogger("xtractr.environment")


def _hash_file(filepath: str) -> str:
    """Compute SHA-256 of a single file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def compute_tool_hash(project_root: str = None) -> str:
    """
    Walk core/, orchestrator/, plugins/ and compute a Merkle root
    of all .py file hashes. This proves the exact tool version used.
    """
    if project_root is None:
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    dirs_to_scan = ["core", "orchestrator", "plugins"]
    file_hashes = []

    for dirname in dirs_to_scan:
        scan_dir = os.path.join(project_root, dirname)
        if not os.path.isdir(scan_dir):
            continue

        for root, _, files in os.walk(scan_dir):
            for fname in sorted(files):
                if fname.endswith(".py"):
                    fpath = os.path.join(root, fname)
                    h = _hash_file(fpath)
                    file_hashes.append(h)

    if not file_hashes:
        return hashlib.sha256(b"NO_SOURCE_FILES").hexdigest()

    root_hash = compute_merkle_root(file_hashes)
    logger.info(f"Tool Environment Hash Root: {root_hash[:16]}... ({len(file_hashes)} files)")
    return root_hash


def log_environment(db, project_root: str = None):
    """
    Compute tool hash and log it as a custody event.
    Should be called immediately after CASE_INIT.
    """
    tool_hash = compute_tool_hash(project_root)
    db.log_event(
        "ENVIRONMENT_HASH",
        f"Tool source Merkle root: {tool_hash}",
        source_hash=tool_hash,
        actor="SYSTEM"
    )
    db.set_metadata("tool_environment_hash", tool_hash)
    return tool_hash
