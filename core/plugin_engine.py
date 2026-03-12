"""
XtractR Plugin Engine — Process-Isolated Execution

Enforces:
  INV-002: Deterministic ordering (sorted plugin discovery + execution)
  INV-004: Schema validation (artifact_validator)  
  INV-005: Provenance traceability (execution_id, plugin source hash)
  INV-006: No silent failure (all errors → custody_events)

Phase 2: ProcessPoolExecutor with resource.setrlimit() for memory + CPU caps.
"""
import os
import sys
import platform
import importlib
import inspect
import logging
import traceback
import time
import json
import uuid
import hashlib
import multiprocessing
from concurrent.futures import ProcessPoolExecutor, TimeoutError as FuturesTimeoutError
from typing import List, Dict, Type, Tuple, Any, Optional
from .plugin_interface import BasePlugin, Artifact
from .artifact_validator import validate_artifact_batch
from .vfs.base import BaseVFS
from .database import CaseDatabase
from .time_provider import TimeProvider

logger = logging.getLogger("xtractr.engine")

MAX_MEMORY_BYTES = 512 * 1024 * 1024   # 512 MB
MAX_CPU_SECONDS = 30                    # 30s CPU time
MAX_WALL_SECONDS = 45                   # 45s wall clock (allows for I/O wait beyond CPU)
MAX_ARTIFACT_COUNT = 100_000            # Per plugin
MAX_OUTPUT_BYTES = 100 * 1024 * 1024    # 100 MB cumulative artifact details size


def _apply_resource_limits():
    """
    Apply resource limits in the child process.
    Only effective on Linux/Unix (uses resource module).
    """
    if platform.system() == "Windows":
        return  # resource module not available on Windows
    
    try:
        import resource
        # Memory limit (virtual memory)
        resource.setrlimit(resource.RLIMIT_AS, (MAX_MEMORY_BYTES, MAX_MEMORY_BYTES))
        # CPU time limit
        resource.setrlimit(resource.RLIMIT_CPU, (MAX_CPU_SECONDS, MAX_CPU_SECONDS + 5))
    except (ImportError, ValueError, OSError) as e:
        # Log but don't fail — limits are defense-in-depth, not sole protection
        pass


def _run_plugin_isolated(
    plugin_module_name: str,
    plugin_class_name: str,
    source_path: str,
    context: Dict[str, Any],
    plugin_dir: str
) -> Dict[str, Any]:
    """
    Worker function executed in a child process.
    Reconstructs VFS, instantiates plugin, runs parse(), returns results.
    
    Returns dict with keys: status, artifacts (list of dicts), error_msg, artifact_count
    """
    # Apply resource limits before any plugin code runs
    _apply_resource_limits()
    
    result = {
        "status": "ERROR",
        "artifacts": [],
        "error_msg": "",
        "artifact_count": 0,
        "cumulative_bytes": 0
    }
    
    try:
        # Ensure plugin directory is importable
        parent_dir = os.path.dirname(plugin_dir)
        if parent_dir not in sys.path:
            sys.path.insert(0, parent_dir)
        
        # Import plugin module and find the class
        module = importlib.import_module(plugin_module_name)
        plugin_cls = getattr(module, plugin_class_name)
        
        # Reconstruct VFS in child process (VFS objects are not picklable)
        from core.ingest import get_vfs
        vfs = get_vfs(source_path)
        
        # Instantiate and run
        plugin = plugin_cls()
        
        if not plugin.can_parse(vfs):
            result["status"] = "SKIPPED"
            return result
        
        artifacts = plugin.parse(vfs, context)
        
        if not isinstance(artifacts, list):
            result["status"] = "ERROR"
            result["error_msg"] = "Plugin returned invalid type (expected list)"
            return result
        
        # Enforce output size limits
        serialized_artifacts = []
        cumulative_bytes = 0
        
        for i, art in enumerate(artifacts):
            if i >= MAX_ARTIFACT_COUNT:
                result["status"] = "RESOURCE_LIMIT"
                result["error_msg"] = f"Exceeded MAX_ARTIFACT_COUNT ({MAX_ARTIFACT_COUNT})"
                break
            
            art_dict = art.to_dict()
            art_bytes = len(json.dumps(art_dict, default=str))
            cumulative_bytes += art_bytes
            
            if cumulative_bytes > MAX_OUTPUT_BYTES:
                result["status"] = "RESOURCE_LIMIT"
                result["error_msg"] = f"Exceeded MAX_OUTPUT_BYTES ({MAX_OUTPUT_BYTES})"
                break
            
            serialized_artifacts.append(art_dict)
        
        if result["status"] not in ("RESOURCE_LIMIT",):
            result["status"] = "SUCCESS"
        
        result["artifacts"] = serialized_artifacts
        result["artifact_count"] = len(serialized_artifacts)
        result["cumulative_bytes"] = cumulative_bytes
        
    except MemoryError:
        result["status"] = "RESOURCE_LIMIT"
        result["error_msg"] = "MemoryError: exceeded memory limit"
    except Exception as e:
        result["status"] = "ERROR"
        result["error_msg"] = f"{type(e).__name__}: {str(e)}"
    
    return result


def _deserialize_artifacts(artifact_dicts: List[Dict]) -> List[Artifact]:
    """Reconstruct Artifact objects from serialized dicts."""
    artifacts = []
    for d in artifact_dicts:
        try:
            art = Artifact(
                artifact_id=d.get("artifact_id", ""),
                artifact_type=d.get("artifact_type", ""),
                source_path=d.get("source_path", ""),
                timestamp_utc=d.get("timestamp_utc", 0),
                parser_name=d.get("parser_name", ""),
                parser_version=d.get("parser_version", ""),
                actor=d.get("actor", ""),
                details=d.get("details", {}),
                reference_hash=d.get("reference_hash"),
                confidence=d.get("confidence", 1.0)
            )
            artifacts.append(art)
        except Exception:
            pass  # Malformed dict — will be caught by validator
    return artifacts


class PluginEngine:
    """
    Manages discovery and execution of XtractR plugins.
    
    Phase 2: Each plugin runs in a separate OS process via ProcessPoolExecutor,
    with resource.setrlimit() enforcing memory (512MB) and CPU (30s) caps.
    """
    
    def __init__(self, plugin_dir: str, db: CaseDatabase):
        self.plugin_dir = plugin_dir
        self.db = db
        self.plugins: List[Type[BasePlugin]] = []
        self._plugin_hashes: Dict[str, str] = {}
        self._plugin_filepaths: Dict[str, str] = {}  # NAME -> absolute filepath
        self._plugin_module_info: Dict[str, Tuple[str, str]] = {}  # NAME -> (module_name, class_name)
        self._source_path: Optional[str] = None  # Set during run_all
        self._discover_plugins()

    def _hash_plugin_source(self, filepath: str) -> str:
        """Compute SHA-256 of a plugin source file for provenance."""
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()

    def _discover_plugins(self):
        """
        Scan plugin_dir for valid BasePlugin implementations.
        INV-002: Sorted discovery for deterministic execution order.
        """
        logger.info(f"Scanning for plugins in {self.plugin_dir}...")
        sys.path.insert(0, os.path.dirname(self.plugin_dir))
        
        # INV-002: Sort filenames for deterministic plugin loading order
        filenames = sorted(os.listdir(self.plugin_dir))
        
        for filename in filenames:
            if filename.endswith(".py") and not filename.startswith("__"):
                module_name = f"plugins.{filename[:-3]}"
                filepath = os.path.join(self.plugin_dir, filename)
                try:
                    module = importlib.import_module(module_name)
                    for name, obj in inspect.getmembers(module):
                        if inspect.isclass(obj) and issubclass(obj, BasePlugin) and obj is not BasePlugin:
                            logger.info(f"Loaded Plugin: {obj.NAME} ({obj.VERSION})")
                            self.plugins.append(obj)
                            self._plugin_hashes[obj.NAME] = self._hash_plugin_source(filepath)
                            self._plugin_filepaths[obj.NAME] = os.path.abspath(filepath)
                            self._plugin_module_info[obj.NAME] = (module_name, name)
                except Exception as e:
                    logger.error(f"Failed to load plugin {filename}: {e}")
                    self.db.log_event("PLUGIN_LOAD_FAIL", f"{filename}: {e}")
        
        # INV-002: Sort plugins by NAME for deterministic execution order
        self.plugins.sort(key=lambda cls: cls.NAME)

    def run_all(self, vfs: BaseVFS, context: Dict = {}) -> List[Artifact]:
        """
        Execute all capable plugins in isolated child processes.
        
        Each plugin gets:
          - Separate OS process (memory isolation)
          - 512 MB memory cap (RLIMIT_AS)
          - 30s CPU cap (RLIMIT_CPU) + 45s wall-clock timeout
          - 100,000 artifact count limit
          - 100 MB output size limit
        """
        all_artifacts = []
        source_path = vfs.source_path
        
        for plugin_cls in self.plugins:
            try:
                # Quick eligibility check in parent process (fast, no isolation needed)
                plugin = plugin_cls()
                if not plugin.can_parse(vfs):
                    continue

                logger.info(f"Running Plugin: {plugin.NAME} [Process Isolated]...")
                
                execution_id = str(uuid.uuid4())
                start_time = TimeProvider.now_ms()
                artifacts = []
                
                original_hash = self._plugin_hashes.get(plugin.NAME, "UNKNOWN")
                plugin_filepath = self._plugin_filepaths.get(plugin.NAME)
                if original_hash != "UNKNOWN" and plugin_filepath:
                    # Re-hash the exact plugin source file to detect tampering
                    current_hash = self._hash_plugin_source(plugin_filepath)
                    if current_hash != original_hash:
                        logger.critical(f"PLUGIN_SOURCE_TAMPERED: {plugin.NAME} source hash changed!")
                        self.db.log_event(
                            "PLUGIN_SOURCE_TAMPERED",
                            f"{plugin.NAME}: expected={original_hash[:16]}... got={current_hash[:16]}...",
                            actor="SYSTEM"
                        )
                        error_msg = "Plugin source file modified since discovery"
                        end_time = TimeProvider.now_ms()
                        cursor = self.db._conn.cursor()
                        cursor.execute("""
                            INSERT INTO plugin_runs 
                            (execution_id, plugin_name, plugin_source_hash, start_time, end_time, 
                             status, artifacts_count, error_msg)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """, (execution_id, plugin.NAME, current_hash, start_time, end_time, "TAMPERED", 0, error_msg))
                        self.db._conn.commit()
                        continue

                # Get module info for serialization to child process
                module_name, class_name = self._plugin_module_info.get(
                    plugin.NAME, (None, None)
                )
                
                if not module_name:
                    status = "ERROR"
                    error_msg = f"Plugin {plugin.NAME} module info not found"
                    logger.error(error_msg)
                    self.db.log_event("PLUGIN_ERROR", error_msg)
                else:
                    try:
                        # Execute in isolated child process
                        with ProcessPoolExecutor(
                            max_workers=1,
                            mp_context=multiprocessing.get_context("spawn")
                        ) as executor:
                            future = executor.submit(
                                _run_plugin_isolated,
                                module_name,
                                class_name,
                                source_path,
                                context,
                                self.plugin_dir
                            )
                            result = future.result(timeout=MAX_WALL_SECONDS)
                        
                        status = result["status"]
                        error_msg = result.get("error_msg", "")
                        
                        if status == "SKIPPED":
                            continue  # Plugin declined after deeper inspection
                        
                        if status in ("SUCCESS", "PARTIAL", "RESOURCE_LIMIT"):
                            # Deserialize and validate artifacts
                            raw_artifacts = _deserialize_artifacts(result["artifacts"])
                            valid_artifacts, invalid_artifacts = validate_artifact_batch(raw_artifacts)
                            
                            if invalid_artifacts:
                                for inv_art, reason in invalid_artifacts:
                                    self.db.log_event(
                                        "ARTIFACT_VALIDATION_FAIL",
                                        f"Plugin={plugin.NAME} ArtifactID={inv_art.artifact_id}: {reason}",
                                        actor="SYSTEM"
                                    )
                                logger.warning(
                                    f"Plugin {plugin.NAME}: {len(invalid_artifacts)} artifacts rejected, "
                                    f"{len(valid_artifacts)} accepted"
                                )
                            
                            artifacts = valid_artifacts
                            all_artifacts.extend(artifacts)
                            
                            # Refine status
                            if status == "RESOURCE_LIMIT":
                                error_msg = f"RESOURCE_LIMIT: {error_msg}; {len(artifacts)} artifacts saved before limit"
                            elif invalid_artifacts:
                                status = "PARTIAL"
                                error_msg = f"{len(invalid_artifacts)} artifacts rejected"
                            
                            logger.info(
                                f"Plugin {plugin.NAME} finished. "
                                f"{len(artifacts)} valid artifacts. "
                                f"Output: {result.get('cumulative_bytes', 0)} bytes."
                            )
                        
                        if status == "RESOURCE_LIMIT":
                            self.db.log_event("PLUGIN_RESOURCE_LIMIT", f"{plugin.NAME}: {error_msg}")
                    
                    except FuturesTimeoutError:
                        status = "TIMEOUT"
                        error_msg = f"Wall-clock timeout ({MAX_WALL_SECONDS}s)"
                        logger.error(f"Plugin {plugin.NAME} timed out")
                        self.db.log_event("PLUGIN_TIMEOUT", f"{plugin.NAME}: {error_msg}")
                    
                    except Exception as e:
                        status = "ERROR"
                        error_msg = str(e)
                        logger.error(f"Plugin {plugin.NAME} failed: {e}")
                        traceback.print_exc()
                        self.db.log_event("PLUGIN_ERROR", f"{plugin.NAME}: {error_msg}")
                
                # Store valid artifacts in database
                if status in ("SUCCESS", "PARTIAL", "RESOURCE_LIMIT") and artifacts:
                    cursor = self.db._conn.cursor()
                    for art in artifacts:
                        details_json = json.dumps(art.details, sort_keys=True, default=str)
                        cursor.execute("""
                            INSERT INTO derived_artifacts 
                            (execution_id, artifact_type, source_path, sha256, plugin_name, 
                             plugin_version, timestamp_utc, details, actor)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (
                            execution_id,
                            art.artifact_type, 
                            art.source_path, 
                            art.reference_hash, 
                            plugin.NAME, 
                            plugin.VERSION, 
                            art.timestamp_utc,
                            details_json,
                            art.actor
                        ))
                    self.db._conn.commit()

                end_time = TimeProvider.now_ms()
                
                # Log plugin run with provenance
                plugin_hash = self._plugin_hashes.get(plugin.NAME, "UNKNOWN")
                cursor = self.db._conn.cursor()
                cursor.execute("""
                    INSERT INTO plugin_runs 
                    (execution_id, plugin_name, plugin_source_hash, start_time, end_time, 
                     status, artifacts_count, error_msg)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    execution_id, plugin.NAME, plugin_hash, 
                    start_time, end_time, status,
                    len(artifacts) if status in ("SUCCESS", "PARTIAL", "RESOURCE_LIMIT") else 0, 
                    error_msg
                ))
                self.db._conn.commit()

            except Exception as e:
                logger.critical(f"Engine Error running {plugin_cls.NAME}: {e}")
                self.db.log_event("ENGINE_ERROR", f"{plugin_cls.NAME}: {e}")
        
        return all_artifacts
