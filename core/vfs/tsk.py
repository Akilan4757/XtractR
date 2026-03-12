import os
import sys
import logging
from typing import List, BinaryIO, Generator, Tuple
from .base import BaseVFS

logger = logging.getLogger("xtractr.vfs.tsk")

try:
    import pytsk3
except ImportError:
    pytsk3 = None
    logger.warning("pytsk3 not installed. Image support disabled.")

class TskVFS(BaseVFS):
    """
    VFS implementation for Disk Images (RAW, E01) using SleuthKit (pytsk3).
    """

    def __init__(self, source_path: str, offset_byte: int = 0):
        super().__init__(source_path)
        if not pytsk3:
            raise ImportError("pytsk3 environment missing")
        
        self.img_info = pytsk3.Img_Info(self.source_path)
        try:
            self.fs_info = pytsk3.FS_Info(self.img_info, offset=offset_byte)
        except IOError as e:
            raise ValueError(f"Could not open filesystem at offset {offset_byte}: {e}")
        
        self.root_dir = self.fs_info.open_dir(path="/")

    def _get_file_object(self, path: str):
        path = self._normalize_path(path)
        if not path.startswith("/"): path = "/" + path
        try:
            return self.fs_info.open_dir(path=path)
        except IOError:
            try:
                return self.fs_info.open_file(path=path)
            except IOError:
                return None

    def listdir(self, path: str) -> List[str]:
        obj = self._get_file_object(path)
        if not obj: return []
        
        results = []
        # Check if directory
        if hasattr(obj, "iternames"): # It's a directory
            for f in obj:
                name = f.info.name.name.decode("utf-8")
                if name in [".", ".."]: continue
                results.append(name)
        return results

    def is_file(self, path: str) -> bool:
        obj = self._get_file_object(path)
        if not obj: return False
        return not hasattr(obj, "iternames") and obj.info.meta.type == pytsk3.TSK_FS_META_TYPE_REG

    def is_dir(self, path: str) -> bool:
        obj = self._get_file_object(path)
        if not obj: return False
        
        # pytsk3 directory object
        meta_type = obj.info.meta.type
        return meta_type == pytsk3.TSK_FS_META_TYPE_DIR

    def open(self, path: str, mode: str = "rb") -> BinaryIO:
        if "w" in mode or "a" in mode or "+" in mode:
            raise PermissionError(f"Write access forbidden in VFS: {path}")
        
        file_obj = self._get_file_object(path)
        if not file_obj or not hasattr(file_obj, "read_random"):
            raise FileNotFoundError(f"File not found in image: {path}")

        # Return a file-like wrapper for pytsk3 file object
        return TskFileWrapper(file_obj)

    def stat(self, path: str) -> dict:
        obj = self._get_file_object(path)
        if not obj: return {}
        
        meta = obj.info.meta
        return {
            "size": meta.size,
            "mtime": meta.mtime,
            "ctime": meta.crtime,
            "atime": meta.atime,
            "mode": meta.mode
        }

    def walk(self, top: str) -> Generator[Tuple[str, List[str], List[str]], None, None]:
        # Recursive walk logic for TSK
        # TSK directories are iterable
        
        queue = [top]
        
        while queue:
            current_path = queue.pop(0)
            dirs = []
            files = []
            
            try:
                directory = self._get_file_object(current_path)
                if not directory or not hasattr(directory, "iternames"): continue

                for entry in directory:
                    name = entry.info.name.name.decode("utf-8")
                    if name in [".", ".."]: continue
                    
                    if entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                        dirs.append(name)
                        queue.append(os.path.join(current_path, name))
                    elif entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_REG:
                        files.append(name)
                
                yield current_path, dirs, files

            except IOError:
                continue

class TskFileWrapper:
    """Read-only file-like object for pytsk3 file handles."""
    def __init__(self, tsk_file):
        self._file = tsk_file
        self._offset = 0
        self._size = tsk_file.info.meta.size

    def read(self, size: int = -1) -> bytes:
        if size == -1: size = self._size - self._offset
        data = self._file.read_random(self._offset, size)
        self._offset += len(data)
        return data

    def seek(self, offset: int, whence: int = 0):
        if whence == 0: self._offset = offset
        elif whence == 1: self._offset += offset
        elif whence == 2: self._offset = self._size + offset
        
    def tell(self) -> int:
        return self._offset

    def close(self):
        pass
