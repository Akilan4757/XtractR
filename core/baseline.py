import time
import logging
from typing import List, Dict, Tuple
from .database import CaseDatabase
from .vfs.base import BaseVFS
from .integrity import hash_file

logger = logging.getLogger("xtractr.baseline")

def create_baseline(vfs: BaseVFS, db: CaseDatabase) -> Tuple[int, int]:
    """
    Scan VFS and populate baseline_files table.
    Returns (files_hashed, total_bytes).
    """
    count = 0
    total_bytes = 0
    
    logger.info("Starting Baseline Hashing...")
    start_time = time.time()

    for root, dirs, files in vfs.walk(""):
        for file in files:
            path = f"{root}/{file}" if root else file
            
            try:
                # Stat
                stats = vfs.stat(path)
                size = stats.get("size", 0)
                mtime = int(stats.get("mtime", 0))

                # Hash
                with vfs.open(path) as f:
                    sha256 = hash_file(f)
                
                # Store
                db.add_baseline_file(path, size, mtime, sha256)
                
                count += 1
                total_bytes += size
                
                if count % 100 == 0:
                    logger.debug(f"Hashed {count} files...")
                    
            except Exception as e:
                logger.error(f"Failed to baseline {path}: {e}")
                db.log_event("BASELINE_ERROR", f"{path}: {e}")

    duration = time.time() - start_time
    logger.info(f"Baseline complete: {count} files ({total_bytes} bytes) in {duration:.2f}s")
    
    db.log_event("BASELINE_COMPLETE", f"Scanned {count} files, {total_bytes} bytes", "N/A", "SYSTEM")
    return count, total_bytes

def check_drift(vfs: BaseVFS, db: CaseDatabase) -> Dict[str, List[str]]:
    """
    Compare current VFS state against DB baseline.
    Returns dict of drift events: { 'modified': [], 'missing': [], 'new': [] }
    """
    drift = {
        "modified": [],
        "missing": [],
        "new": []
    }
    
    # Load all baseline into memory (for MVP size)
    # For massive cases, we'd stream cursor
    cursor = db._conn.cursor()
    cursor.execute("SELECT path, sha256, size FROM baseline_files")
    baseline_map = {row["path"]: row for row in cursor.fetchall()}
    
    # Scan VFS
    scanned_paths = set()
    
    for root, dirs, files in vfs.walk(""):
        for file in files:
            path = f"{root}/{file}" if root else file
            scanned_paths.add(path)
            
            if path not in baseline_map:
                drift["new"].append(path)
                continue
            
            # Check Hash (if content check requested - usually separate Verify tool)
            # But let's check size/hash here as per Phase 3 requirements
            base = baseline_map[path]
            try:
                with vfs.open(path) as f:
                    curr_hash = hash_file(f)
                
                if curr_hash != base["sha256"]:
                    drift["modified"].append(f"{path} (Hash Mismatch)")
            except Exception as e:
                drift["modified"].append(f"{path} (Read Error: {e})")

    # Check Missing
    for path in baseline_map:
        if path not in scanned_paths:
            drift["missing"].append(path)
            
    return drift
