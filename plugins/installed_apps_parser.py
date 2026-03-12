"""
Installed Apps Parser Plugin — XtractR Forensic Platform
Parses packages.xml / packages.list from Android system partitions.
"""
import os
import xml.etree.ElementTree as ET
import logging
from typing import List, Dict, Any
from core.plugin_interface import BasePlugin, Artifact
from core.vfs.base import BaseVFS
import tempfile

logger = logging.getLogger("xtractr.plugin.installed_apps")


class InstalledAppsParser(BasePlugin):
    NAME = "Installed Apps Parser"
    VERSION = "1.1.0"
    DESCRIPTION = "Parses packages.xml / packages.list for installed application inventory"

    def can_parse(self, vfs: BaseVFS) -> bool:
        return True

    def parse(self, vfs: BaseVFS, context: Dict[str, Any]) -> List[Artifact]:
        artifacts = []
        files_found = []

        for root, dirs, files in vfs.walk(""):
            if "packages.xml" in files:
                files_found.append((os.path.join(root, "packages.xml"), "xml"))
            if "packages.list" in files:
                files_found.append((os.path.join(root, "packages.list"), "list"))

        for path, fmt in files_found:
            try:
                content = vfs.read_bytes(path)
                if fmt == "list":
                    for line in content.decode('utf-8', errors='ignore').splitlines():
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            pkg = parts[0]
                            uid = parts[1]
                            artifacts.append(Artifact(
                                artifact_id=f"app_{pkg}",
                                artifact_type="INSTALLED_APP",
                                source_path=path,
                                timestamp_utc=0,
                                parser_name=self.NAME,
                                parser_version=self.VERSION,
                                actor="DEVICE",
                                details={
                                    "package": pkg,
                                    "uid": uid,
                                    "data_dir": parts[3] if len(parts) > 3 else "",
                                },
                            ))
                elif fmt == "xml":
                    with tempfile.NamedTemporaryFile(suffix=".xml", delete=True) as tmp:
                        tmp.write(content)
                        tmp.flush()
                        tree = ET.parse(tmp.name)
                        xml_root = tree.getroot()
                        for package in xml_root.findall("package"):
                            name = package.get("name")
                            code_path = package.get("codePath", "")
                            ft = package.get("ft", "")       # first install time
                            ut = package.get("ut", "")       # update time
                            version = package.get("version", "")
                            if name:
                                artifacts.append(Artifact(
                                    artifact_id=f"app_{name}",
                                    artifact_type="INSTALLED_APP",
                                    source_path=path,
                                    timestamp_utc=0,
                                    parser_name=self.NAME,
                                    parser_version=self.VERSION,
                                    actor="DEVICE",
                                    details={
                                        "package": name,
                                        "path": code_path,
                                        "version": version,
                                        "first_install": ft,
                                        "last_update": ut,
                                    },
                                ))
            except Exception as e:
                logger.warning(f"[InstalledAppsParser] Failed to process {path}: {e}")

        return artifacts
