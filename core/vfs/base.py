import abc
import os
from typing import List, BinaryIO, Generator, Tuple, Optional, Union
import logging

logger = logging.getLogger("xtractr.vfs")

class BaseVFS(abc.ABC):
    """
    Abstract Base Class for XtractR Read-Only Virtual Filesystem.
    All evidence sources (Directory, Archive, Image) must implement this.
    """

    def __init__(self, source_path: str):
        self.source_path = os.path.abspath(source_path)
        if not os.path.exists(self.source_path):
            raise FileNotFoundError(f"Evidence source not found: {self.source_path}")

    @abc.abstractmethod
    def listdir(self, path: str) -> List[str]:
        """List contents of a directory."""
        pass

    @abc.abstractmethod
    def is_file(self, path: str) -> bool:
        """Check if path is a file."""
        pass

    @abc.abstractmethod
    def is_dir(self, path: str) -> bool:
        """Check if path is a directory."""
        pass

    @abc.abstractmethod
    def open(self, path: str, mode: str = "rb") -> BinaryIO:
        """
        Open a file for reading. 
        CRITICAL: Must enforce read-only mode.
        """
        pass

    @abc.abstractmethod
    def stat(self, path: str) -> dict:
        """
        Return metadata: size, mtime, ctime, mode.
        """
        pass
    
    @abc.abstractmethod
    def walk(self, top: str) -> Generator[Tuple[str, List[str], List[str]], None, None]:
        """
        Recursive directory walk similar to os.walk().
        Yields (root, dirs, files).
        """
        pass

    def read_bytes(self, path: str, max_bytes: Optional[int] = None) -> bytes:
        """
        Helper to read bytes from a file.
        """
        try:
            with self.open(path, "rb") as f:
                if max_bytes:
                    return f.read(max_bytes)
                return f.read()
        except Exception as e:
            logger.error(f"Read error at {path}: {e}")
            raise

    def get_backend_type(self) -> str:
        """Return the type of VFS backend (e.g., 'dir', 'zip', 'tsk')."""
        return self.__class__.__name__

    def _normalize_path(self, path: str) -> str:
        """Strip leading slashes to ensure relative path logic."""
        if path.startswith("/"):
            return path.lstrip("/")
        return path
