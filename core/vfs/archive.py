import zipfile
import tarfile
from typing import List, BinaryIO, Generator, Tuple
from .base import BaseVFS
import logging

logger = logging.getLogger("xtractr.vfs.archive")

class ArchiveVFS(BaseVFS):
    """
    VFS implementation for ZIP and TAR archives.
    Treats the archive as a transparent read-only filesystem.
    """

    def __init__(self, source_path: str):
        super().__init__(source_path)
        self.type = None
        if zipfile.is_zipfile(self.source_path):
            self.type = "zip"
            self._handle = zipfile.ZipFile(self.source_path, 'r')
        elif tarfile.is_tarfile(self.source_path):
            self.type = "tar"
            self._handle = tarfile.open(self.source_path, 'r')
        else:
            raise ValueError(f"Unsupported archive type: {self.source_path}")

    def listdir(self, path: str) -> List[str]:
        path = self._normalize_path(path)
        if path and not path.endswith('/'):
            path += '/'
        
        results = set()
        if self.type == "zip":
            for name in self._handle.namelist():
                if name.startswith(path):
                    # Get immediate child
                    suffix = name[len(path):]
                    if not suffix: continue
                    parts = suffix.split('/', 1)
                    results.add(parts[0])
        elif self.type == "tar":
            for member in self._handle.getnames():
                if member.startswith(path):
                     suffix = member[len(path):]
                     if not suffix: continue
                     parts = suffix.split('/', 1)
                     results.add(parts[0])
        
        return list(results)

    def is_file(self, path: str) -> bool:
        path = self._normalize_path(path)
        try:
            if self.type == "zip":
                # ZipFile doesn't have isfile, check if info exists and not dir
                info = self._handle.getinfo(path)
                return not info.is_dir()
            elif self.type == "tar":
                member = self._handle.getmember(path)
                return member.isfile()
        except KeyError:
            return False

    def is_dir(self, path: str) -> bool:
        path = self._normalize_path(path)
        # Root is always a dir
        if path == "" or path == ".": return True

        try:
            if self.type == "zip":
                # Zips mimic dirs by trailing slash usually
                # We also check if it is a prefix of other files
                try:
                    info = self._handle.getinfo(path + "/")
                    return info.is_dir()
                except KeyError:
                    # If explicitly stored as dir, it works. 
                    # If implict, check if it prefix matches any file
                    for name in self._handle.namelist():
                        if name.startswith(path + "/"):
                            return True
                    return False

            elif self.type == "tar":
                try:
                    member = self._handle.getmember(path)
                    return member.isdir()
                except KeyError:
                     # Check implicit dir
                    for name in self._handle.getnames():
                        if name.startswith(path + "/"):
                            return True
                    return False
        except KeyError:
            return False

    def open(self, path: str, mode: str = "rb") -> BinaryIO:
        if "w" in mode or "a" in mode or "+" in mode:
            raise PermissionError(f"Write access forbidden in VFS: {path}")
        
        path = self._normalize_path(path)
        try:
            if self.type == "zip":
                return self._handle.open(path, 'r')
            elif self.type == "tar":
                extract = self._handle.extractfile(path)
                if extract is None:
                    raise FileNotFoundError(f"Could not extract {path}")
                return extract
        except KeyError:
            raise FileNotFoundError(f"File not found in archive: {path}")

    def stat(self, path: str) -> dict:
        path = self._normalize_path(path)
        try:
            if self.type == "zip":
                info = self._handle.getinfo(path)
                # ZipInfo.date_time is tuple (YYYY, M, D, H, M, S)
                # No easy epoch conversion without datetime, returning mock for now or 0
                return {
                    "size": info.file_size,
                    "mtime": 0, # TODO: Convert date_time to epoch
                    "mode": 0o444
                }
            elif self.type == "tar":
                member = self._handle.getmember(path)
                return {
                    "size": member.size,
                    "mtime": member.mtime,
                    "mode": member.mode
                }
        except KeyError:
            return {}

    def walk(self, top: str) -> Generator[Tuple[str, List[str], List[str]], None, None]:
        # Simple recursive implementation on top of listdir/isdir/isfile
        # Optimizing this for archives is hard without internal tree structure
        
        # Helper stack-based walk or just using the flatten list
        # Since archives are usually small enough to list all, we can iterate all members
        # and filter by prefix 'top'
        
        top = self._normalize_path(top)
        if top and not top.endswith('/'): top += '/'
        
        # Build tree in memory for walk
        # This is a bit inefficient for massive archives but robust
        tree = {}
        
        names = []
        if self.type == "zip":
            names = self._handle.namelist()
        else:
            names = self._handle.getnames()
            
        for name in names:
            if not name.startswith(top): continue
            
            # Relativize
            rel = name[len(top):]
            if rel == "": continue
            
            parts = rel.strip('/').split('/')
            
            current = tree
            for part in parts[:-1]:
                if part not in current:
                    current[part] = {}
                current = current[part]
            
            last = parts[-1]
            if name.endswith('/'):
                 if last not in current: current[last] = {}
            else:
                 current[last] = "__FILE__"

        # Now yield generator
        def _recurse(current_path, node):
            dirs = []
            files = []
            for k, v in node.items():
                if v == "__FILE__":
                    files.append(k)
                else:
                    dirs.append(k)
            
            yield current_path, dirs, files
            
            for d in dirs:
                yield from _recurse(os.path.join(current_path, d), node[d])

        yield from _recurse(top.rstrip('/'), tree)

    def close(self):
        if self._handle:
            self._handle.close()
