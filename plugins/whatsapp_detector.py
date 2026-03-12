import os
from typing import List, Dict, Any
from core.plugin_interface import BasePlugin, Artifact
from core.vfs.base import BaseVFS

class WhatsAppDetector(BasePlugin):
    NAME = "WhatsApp Detector"
    VERSION = "1.0.0"
    DESCRIPTION = "Detects WhatsApp databases (Encrypted)"
    
    def can_parse(self, vfs: BaseVFS) -> bool:
        return True

    def parse(self, vfs: BaseVFS, context: Dict[str, Any]) -> List[Artifact]:
        artifacts = []
        for root, dirs, files in vfs.walk(""):
            for f in files:
                if f == "msgstore.db" or (f.startswith("msgstore") and f.endswith(".db.crypt14")):
                    path = os.path.join(root, f)
                    artifacts.append(Artifact(
                        artifact_id=f"wa_db_{hash(path)}",
                        artifact_type="ENCRYPTED_DB",
                        source_path=path,
                        timestamp_utc=0,
                        parser_name=self.NAME,
                        parser_version=self.VERSION,
                        actor="DEVICE",
                        details={
                            "info": "Encrypted WhatsApp Database detected.",
                            "filename": f
                        },
                        confidence=1.0
                    ))
        return artifacts
