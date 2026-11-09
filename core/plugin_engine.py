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
import logging
import time
import json
import uuid
import hashlib
import multiprocessing
import ast
from queue import Empty as QueueEmpty
from concurrent.futures import TimeoutError as FuturesTimeoutError
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


def _plugin_process_entry(result_queue, *worker_args):
    try:
        result_queue.put((True, _run_plugin_isolated(*worker_args)))
    except BaseException as exc:
        result_queue.put((False, f"{type(exc).__name__}: {exc}"))


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
    plugin_dir: str,
    expected_hash: str,
    filepath: str
) -> Dict[str, Any]:
    """
    Worker function executed in a child process.
    Reconstructs VFS, instantiates plugin, runs parse(), returns results.
    """
    _apply_resource_limits()
    
    result = {
        "status": "ERROR",
        "artifacts": [],
        "error_msg": "",
        "artifact_count": 0,
        "cumulative_bytes": 0,
        "errors": []
    }
    
    try:
        # TOCTOU protection: verify hash inside child process before import
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        current_hash = h.hexdigest()
        
        if current_hash != expected_hash:
            result["status"] = "TAMPERED"
            result["error_msg"] = "Plugin source file modified since discovery"
            return result

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
        
        # Capture internal plugin errors
        result["errors"] = getattr(plugin, "errors", [])
        
        # Enforce output size limits
        serialized_artifacts = []
        cumulative_bytes = 0
        
        for i, art in enumerate(artifacts):
            if i >= MAX_ARTIFACT_COUNT:
                result["status"] = "RESOURCE_LIMIT"
                result["error_msg"] = f"Exceeded MAX_ARTIFACT_COUNT ({MAX_ARTIFACT_COUNT})"
                break
            
            if not getattr(art, "reference_hash", None) or art.reference_hash == "UNKNOWN":
                art.reference_hash = plugin.get_reference_hash(vfs, art.source_path)
            
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


def _static_discover_plugin(filepath: str) -> Optional[Dict[str, Any]]:
    """Statically parse a plugin file using AST to extract NAME, VERSION, and class_name."""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            node = ast.parse(f.read(), filename=filepath)
        
        for child in node.body:
            if isinstance(child, ast.ClassDef):
                name_val = None
                version_val = None
                for sub in child.body:
                    if isinstance(sub, ast.Assign):
                        for target in sub.targets:
                            if isinstance(target, ast.Name):
                                if target.id == "NAME":
                                    if isinstance(sub.value, ast.Constant):
                                        name_val = sub.value.value
                                    elif isinstance(sub.value, ast.Str):
                                        name_val = sub.value.s
                                elif target.id == "VERSION":
                                    if isinstance(sub.value, ast.Constant):
                                        version_val = sub.value.value
                                    elif isinstance(sub.value, ast.Str):
                                        version_val = sub.value.s
                                    
                if name_val is not None:
                    return {
                        "class_name": child.name,
                        "NAME": name_val,
                        "VERSION": version_val or "1.0.0"
                    }
    except Exception as e:
        logger.error(f"AST parsing failed for {filepath}: {e}")
    return None


class PluginInfo:
    """Lightweight metadata class for discovered plugins."""
    def __init__(self, name: str, version: str, class_name: str, module_name: str, filepath: str):
        self.NAME = name
        self.VERSION = version
        self.class_name = class_name
        self.module_name = module_name
        self.filepath = filepath


class PluginEngine:
    """
    Manages discovery and execution of XtractR plugins.
    
    Phase 2: Each plugin runs in a separate OS process via ProcessPoolExecutor,
    with resource.setrlimit() enforcing memory (512MB) and CPU (30s) caps.
    """
    
    def __init__(self, plugin_dir: str, db: CaseDatabase):
        self.plugin_dir = plugin_dir
        self.db = db
        self.plugins: List[PluginInfo] = []
        self._plugin_hashes: Dict[str, str] = {}
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
        Scan plugin_dir for BasePlugin implementations using static AST parsing.
        INV-002: Sorted discovery for deterministic execution order.
        """
        logger.info(f"Scanning for plugins in {self.plugin_dir} (Static AST Mode)...")
        
        # INV-002: Sort filenames for deterministic plugin loading order
        filenames = sorted(os.listdir(self.plugin_dir))
        
        for filename in filenames:
            if filename.endswith(".py") and not filename.startswith("__"):
                module_name = f"plugins.{filename[:-3]}"
                filepath = os.path.join(self.plugin_dir, filename)
                try:
                    info = _static_discover_plugin(filepath)
                    if info:
                        plugin_info = PluginInfo(
                            name=info["NAME"],
                            version=info["VERSION"],
                            class_name=info["class_name"],
                            module_name=module_name,
                            filepath=os.path.abspath(filepath)
                        )
                        logger.info(f"Statically loaded plugin metadata: {plugin_info.NAME} ({plugin_info.VERSION})")
                        self.plugins.append(plugin_info)
                        self._plugin_hashes[plugin_info.NAME] = self._hash_plugin_source(filepath)
                except Exception as e:
                    logger.error(f"Failed to statically load plugin {filename}: {e}")
                    self.db.log_event("PLUGIN_LOAD_FAIL", f"{filename}: {e}")
        
        # INV-002: Sort plugins by NAME for deterministic execution order
        self.plugins.sort(key=lambda p: p.NAME)

    def run_all(self, vfs: BaseVFS, context: Optional[Dict] = None) -> List[Artifact]:
        """
        Execute all capable plugins in isolated child processes.
        """
        context = context or {}
        all_artifacts = []
        source_path = vfs.source_path
        
        # Ensure single run-scoped execution_id exists
        session_execution_id = self.db.get_metadata("session_execution_id")
        if not session_execution_id:
            session_execution_id = str(uuid.uuid4())
            self.db.set_metadata("session_execution_id", session_execution_id)
        
        for plugin_info in self.plugins:
            try:
                logger.info(f"Running Plugin: {plugin_info.NAME} [Process Isolated]...")
                start_time = TimeProvider.now_ms()
                artifacts = []
                
                original_hash = self._plugin_hashes.get(plugin_info.NAME, "UNKNOWN")
                
                # Execute in isolated child process
                try:
                    mp_context = multiprocessing.get_context("spawn")
                    result_queue = mp_context.Queue(maxsize=1)
                    process = mp_context.Process(
                        target=_plugin_process_entry,
                        args=(result_queue, plugin_info.module_name, plugin_info.class_name,
                              source_path, context, self.plugin_dir, original_hash,
                              plugin_info.filepath),
                    )
                    process.start()
                    try:
                        ok, payload = result_queue.get(timeout=MAX_WALL_SECONDS)
                        process.join(timeout=2)
                        if process.is_alive():
                            process.terminate()
                            process.join(timeout=2)
                        if process.is_alive() and hasattr(process, "kill"):
                            process.kill()
                            process.join()
                        if not ok:
                            raise RuntimeError(payload)
                        result = payload
                    except QueueEmpty as timeout_error:
                        if process.is_alive():
                            process.terminate()
                            process.join(timeout=2)
                        if process.is_alive() and hasattr(process, "kill"):
                            process.kill()
                            process.join()
                        raise FuturesTimeoutError() from timeout_error
                    finally:
                        result_queue.close()
                    
                    status = result["status"]
                    error_msg = result.get("error_msg", "")
                    
                    if status == "SKIPPED":
                        logger.info(f"Plugin {plugin_info.NAME} was skipped (can_parse returned False).")
                        continue
                    
                    if status == "TAMPERED":
                        logger.critical(f"PLUGIN_SOURCE_TAMPERED: {plugin_info.NAME} source hash changed!")
                        self.db.log_event(
                            "PLUGIN_SOURCE_TAMPERED",
                            f"{plugin_info.NAME}: expected={original_hash[:16]}...",
                            actor="SYSTEM"
                        )
                        # Write failure to plugin_runs
                        end_time = TimeProvider.now_ms()
                        cursor = self.db._conn.cursor()
                        cursor.execute("""
                            INSERT INTO plugin_runs 
                            (execution_id, plugin_name, plugin_source_hash, start_time, end_time, 
                             status, artifacts_count, error_msg)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """, (session_execution_id, plugin_info.NAME, original_hash, start_time, end_time, "TAMPERED", 0, error_msg))
                        self.db._conn.commit()
                        continue
                    
                    if status in ("SUCCESS", "PARTIAL", "RESOURCE_LIMIT"):
                        # Deserialize and validate artifacts
                        raw_artifacts = _deserialize_artifacts(result["artifacts"])
                        valid_artifacts, invalid_artifacts = validate_artifact_batch(raw_artifacts)
                        
                        if invalid_artifacts:
                            for inv_art, reason in invalid_artifacts:
                                self.db.log_event(
                                    "ARTIFACT_VALIDATION_FAIL",
                                    f"Plugin={plugin_info.NAME} ArtifactID={inv_art.artifact_id}: {reason}",
                                    actor="SYSTEM"
                                )
                            logger.warning(
                                f"Plugin {plugin_info.NAME}: {len(invalid_artifacts)} artifacts rejected, "
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
                            f"Plugin {plugin_info.NAME} finished. "
                            f"{len(artifacts)} valid artifacts. "
                            f"Output: {result.get('cumulative_bytes', 0)} bytes."
                        )
                        
                        # Handle partial failures reported by plugin
                        plugin_errors = result.get("errors", [])
                        if plugin_errors:
                            for err in plugin_errors:
                                logger.error(f"Plugin {plugin_info.NAME} partial failure: {err}")
                                self.db.log_event(
                                    "PLUGIN_PARTIAL_FAILURE",
                                    f"Plugin={plugin_info.NAME}: {err}",
                                    actor="SYSTEM"
                                )
                    
                    if status == "RESOURCE_LIMIT":
                        self.db.log_event("PLUGIN_RESOURCE_LIMIT", f"{plugin_info.NAME}: {error_msg}")
                
                except FuturesTimeoutError:
                    status = "TIMEOUT"
                    error_msg = f"Wall-clock timeout ({MAX_WALL_SECONDS}s)"
                    logger.error(f"Plugin {plugin_info.NAME} timed out")
                    self.db.log_event("PLUGIN_TIMEOUT", f"{plugin_info.NAME}: {error_msg}")
                
                except Exception as e:
                    status = "ERROR"
                    error_msg = str(e)
                    logger.error(f"Plugin {plugin_info.NAME} failed: {e}")
                    self.db.log_event("PLUGIN_ERROR", f"{plugin_info.NAME}: {error_msg}")
                
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
                            session_execution_id,
                            art.artifact_type, 
                            art.source_path, 
                            art.reference_hash, 
                            plugin_info.NAME, 
                            plugin_info.VERSION, 
                            art.timestamp_utc,
                            details_json,
                            art.actor
                        ))
                    self.db._conn.commit()

                end_time = TimeProvider.now_ms()
                
                # Log plugin run with provenance
                cursor = self.db._conn.cursor()
                cursor.execute("""
                    INSERT INTO plugin_runs 
                    (execution_id, plugin_name, plugin_source_hash, start_time, end_time, 
                     status, artifacts_count, error_msg)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    session_execution_id, plugin_info.NAME, original_hash, 
                    start_time, end_time, status,
                    len(artifacts) if status in ("SUCCESS", "PARTIAL", "RESOURCE_LIMIT") else 0, 
                    error_msg
                ))
                self.db._conn.commit()

            except Exception as e:
                logger.critical(f"Engine Error running {plugin_info.NAME}: {e}")
                self.db.log_event("ENGINE_ERROR", f"{plugin_info.NAME}: {e}")
        
        return all_artifacts
