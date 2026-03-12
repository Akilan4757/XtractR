import os
import glob
from typing import List, BinaryIO, Generator, Tuple
from .base import BaseVFS
import logging

logger = logging.getLogger("xtractr.vfs.dir")

class DirectoryVFS(BaseVFS):
    """
    VFS implementation for standard directory-based evidence (Logical Dumps).
    """

    def __init__(self, source_path: str):
        super().__init__(source_path)
        if not os.path.isdir(self.source_path):
            raise ValueError(f"DirectoryVFS requires a directory, got file: {self.source_path}")

    def _get_real_path(self, path: str) -> str:
        """
        Resolve virtual path to real OS path.
        Prevents traversal out of source_path.
        """
        clean_path = self._normalize_path(path)
        full_path = os.path.normpath(os.path.join(self.source_path, clean_path))
        
        if not full_path.startswith(self.source_path):
            raise PermissionError(f"Path traversal attempted: {path}")
        
        return full_path

    def listdir(self, path: str) -> List[str]:
        real_path = self._get_real_path(path)
        try:
            return os.listdir(real_path)
        except OSError as e:
            logger.warning(f"listdir failed for {path}: {e}")
            return []

    def is_file(self, path: str) -> bool:
        real_path = self._get_real_path(path)
        return os.path.isfile(real_path)

    def is_dir(self, path: str) -> bool:
        real_path = self._get_real_path(path)
        return os.path.isdir(real_path)

    def open(self, path: str, mode: str = "rb") -> BinaryIO:
        if "w" in mode or "a" in mode or "+" in mode:
            raise PermissionError(f"Write access forbidden in VFS: {path}")
        
        real_path = self._get_real_path(path)
        return open(real_path, "rb")

    def stat(self, path: str) -> dict:
        real_path = self._get_real_path(path)
        try:
            stat_res = os.stat(real_path)
            return {
                "size": stat_res.st_size,
                "mtime": stat_res.st_mtime,
                "ctime": stat_res.st_ctime,
                "mode": stat_res.st_mode
            }
        except OSError:
            return {}

    def walk(self, top: str) -> Generator[Tuple[str, List[str], List[str]], None, None]:
        real_top = self._get_real_path(top)
        
        for root, dirs, files in os.walk(real_top):
            # Convert back to virtual path (relative to source root)
            rel_root = os.path.relpath(root, self.source_path)
            if rel_root == ".":
                rel_root = ""
            yield rel_root, dirs, files
