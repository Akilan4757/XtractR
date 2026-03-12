import abc
import json
import time
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from core.vfs.base import BaseVFS

@dataclass
class Artifact:
    """
    Standardized Forensic Artifact.
    ALL plugins must return a list of these objects.
    """
    artifact_id: str  # Unique ID for this artifact instance
    artifact_type: str # e.g., "SMS", "CALL_LOG", "CHROME_HISTORY"
    source_path: str # Path in VFS
    timestamp_utc: int # Unix ms
    parser_name: str
    parser_version: str
    actor: str # Phone number, email, or "DEVICE"
    details: Dict[str, Any] # The actual content
    reference_hash: Optional[str] = None # Hash of source file
    confidence: float = 1.0 # 0.0 - 1.0
    
    def to_dict(self):
        return asdict(self)

class BasePlugin(abc.ABC):
    """
    Abstract Base Class for XtractR Plugins.
    """
    NAME = "BasePlugin"
    VERSION = "0.0.0"
    DESCRIPTION = "Abstract Base"
    AUTHOR = "XtractR Core"
    DEPENDENCIES = []

    @abc.abstractmethod
    def can_parse(self, vfs: BaseVFS) -> bool:
        """
        Quick check if this plugin is applicable to the evidence.
        Should be fast (file existence checks).
        """
        pass

    @abc.abstractmethod
    def parse(self, vfs: BaseVFS, context: Dict[str, Any]) -> List[Artifact]:
        """
        Extract artifacts from the evidence.
        Must operate within sandbox limits (time/memory).
        """
        pass
    
    def normalize_timestamp(self, ts) -> int:
        """Helper to convert various timestamp formats to UTC ms epoch."""
        # Generic implementation, plugins can override or use utils
        if not ts: return 0
        try:
            return int(ts)
        except:
            return 0
