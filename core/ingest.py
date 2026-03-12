import os
import zipfile
import tarfile
import logging
from .vfs.base import BaseVFS
from .vfs.directory import DirectoryVFS
from .vfs.archive import ArchiveVFS
from .vfs.tsk import TskVFS

logger = logging.getLogger("xtractr.ingest")

def get_vfs(source_path: str) -> BaseVFS:
    """
    Factory to return the correct VFS backend for the given source.
    """
    source_path = os.path.abspath(source_path)
    
    if os.path.isdir(source_path):
        logger.info(f"Detected Directory Source: {source_path}")
        return DirectoryVFS(source_path)
    
    if zipfile.is_zipfile(source_path) or tarfile.is_tarfile(source_path):
        logger.info(f"Detected Archive Source: {source_path}")
        return ArchiveVFS(source_path)
    
    # Try Image (TSK) Logic
    # Simple explicit check or try/except
    try:
        # Check standard image headers/extensions
        if source_path.lower().endswith(('.dd', '.raw', '.img', '.e01')):
             logger.info(f"Detected Image Source (TSK): {source_path}")
             return TskVFS(source_path)
    except (ImportError, ValueError) as e:
        logger.warning(f"TSK initialization failed for {source_path}: {e}")
    
    # Fallback or Error
    raise ValueError(f"Unsupported Evidence Type: {source_path}")
