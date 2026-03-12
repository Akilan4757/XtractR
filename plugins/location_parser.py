"""
Location / GPS Parser Plugin — XtractR Forensic Platform
Extracts location data from Android caches, Google location databases,
and cell/WiFi location caches.
"""
import sqlite3
import tempfile
import os
import json
import logging
from typing import List, Dict, Any
from core.plugin_interface import BasePlugin, Artifact
from core.vfs.base import BaseVFS

logger = logging.getLogger("xtractr.plugin.location")

# Common Android location database filenames
LOCATION_DB_NAMES = {
    "cache.cell", "cache.wifi",       # Android CellID/WiFi location cache
    "CachedGeoposition.db",           # WebView geo cache
    "gms_untrusted_snet.db",          # Google Play Services
    "NetworkLocation.db",             # Samsung
    "gmm_storage.db",                 # Google Maps offline tiles (has location hints)
    "gmm_myplaces.db",                # Google Maps saved places
    "da_destination_history",          # Samsung driving history
}

# JSON-based location files
LOCATION_JSON_NAMES = {
    "semantic_location_history",
    "location_history",
}


class LocationParser(BasePlugin):
    NAME = "Location Parser"
    VERSION = "1.0.0"
    DESCRIPTION = "Extracts GPS/Cell/WiFi location data from Android caches and Google services"

    def can_parse(self, vfs: BaseVFS) -> bool:
        return True

    def parse(self, vfs: BaseVFS, context: Dict[str, Any]) -> List[Artifact]:
        artifacts = []

        db_candidates = []
        json_candidates = []

        for root, dirs, files in vfs.walk(""):
            for f in files:
                if f in LOCATION_DB_NAMES:
                    db_candidates.append(os.path.join(root, f))
                elif f.endswith(".json") and any(
                    kw in f.lower() for kw in ("location", "places", "geofence", "geo")
                ):
                    json_candidates.append(os.path.join(root, f))

        # ── SQLite location databases ─────────────────────────────────────────
        for db_path in db_candidates:
            basename = os.path.basename(db_path)
            try:
                with tempfile.NamedTemporaryFile(suffix=".db", delete=True) as tmp:
                    tmp.write(vfs.read_bytes(db_path))
                    tmp.flush()

                    conn = sqlite3.connect(tmp.name)
                    conn.row_factory = sqlite3.Row
                    cursor = conn.cursor()

                    tables = {row[0] for row in cursor.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    ).fetchall()}

                    # Android CellID cache (cache.cell)
                    if basename == "cache.cell" and "cache" in tables:
                        try:
                            cursor.execute("""
                                SELECT latitude, longitude, accuracy, confidence, timestamp
                                FROM cache ORDER BY timestamp ASC
                            """)
                            for row in cursor.fetchall():
                                ts = self.normalize_timestamp(row["timestamp"])
                                artifacts.append(Artifact(
                                    artifact_id=f"loc_cell_{ts}_{abs(hash((row['latitude'], row['longitude'])))}",
                                    artifact_type="LOCATION",
                                    source_path=db_path,
                                    timestamp_utc=ts,
                                    parser_name=self.NAME,
                                    parser_version=self.VERSION,
                                    actor="DEVICE",
                                    details={
                                        "latitude": row["latitude"],
                                        "longitude": row["longitude"],
                                        "accuracy_m": row["accuracy"],
                                        "confidence": row["confidence"],
                                        "provider": "CELL_TOWER",
                                    },
                                ))
                        except sqlite3.OperationalError as e:
                            logger.debug(f"[Location] cache.cell query failed: {e}")

                    # Android WiFi cache
                    if basename == "cache.wifi" and "cache" in tables:
                        try:
                            cursor.execute("""
                                SELECT latitude, longitude, accuracy, timestamp
                                FROM cache ORDER BY timestamp ASC
                            """)
                            for row in cursor.fetchall():
                                ts = self.normalize_timestamp(row["timestamp"])
                                artifacts.append(Artifact(
                                    artifact_id=f"loc_wifi_{ts}_{abs(hash((row['latitude'], row['longitude'])))}",
                                    artifact_type="LOCATION",
                                    source_path=db_path,
                                    timestamp_utc=ts,
                                    parser_name=self.NAME,
                                    parser_version=self.VERSION,
                                    actor="DEVICE",
                                    details={
                                        "latitude": row["latitude"],
                                        "longitude": row["longitude"],
                                        "accuracy_m": row["accuracy"],
                                        "provider": "WIFI",
                                    },
                                ))
                        except sqlite3.OperationalError as e:
                            logger.debug(f"[Location] cache.wifi query failed: {e}")

                    # Samsung driving/destination history
                    if basename == "da_destination_history" and "history" in tables:
                        try:
                            cursor.execute("""
                                SELECT latitude, longitude, timestamp, name, address
                                FROM history ORDER BY timestamp ASC
                            """)
                            for row in cursor.fetchall():
                                ts = self.normalize_timestamp(row["timestamp"])
                                artifacts.append(Artifact(
                                    artifact_id=f"loc_dest_{ts}",
                                    artifact_type="LOCATION",
                                    source_path=db_path,
                                    timestamp_utc=ts,
                                    parser_name=self.NAME,
                                    parser_version=self.VERSION,
                                    actor="DEVICE",
                                    details={
                                        "latitude": row["latitude"],
                                        "longitude": row["longitude"],
                                        "name": row["name"] or "",
                                        "address": row["address"] or "",
                                        "provider": "DESTINATION_HISTORY",
                                    },
                                ))
                        except sqlite3.OperationalError as e:
                            logger.debug(f"[Location] destination history query failed: {e}")

                    # Google Maps saved places (gmm_myplaces.db)
                    if "sync_item" in tables:
                        try:
                            cursor.execute("""
                                SELECT title, latitude, longitude, timestamp
                                FROM sync_item ORDER BY timestamp ASC
                            """)
                            for row in cursor.fetchall():
                                ts = self.normalize_timestamp(row["timestamp"])
                                artifacts.append(Artifact(
                                    artifact_id=f"loc_place_{ts}_{abs(hash(row['title'] or ''))}",
                                    artifact_type="SAVED_PLACE",
                                    source_path=db_path,
                                    timestamp_utc=ts,
                                    parser_name=self.NAME,
                                    parser_version=self.VERSION,
                                    actor="DEVICE",
                                    details={
                                        "title": row["title"] or "",
                                        "latitude": row["latitude"],
                                        "longitude": row["longitude"],
                                        "provider": "GOOGLE_MAPS",
                                    },
                                ))
                        except sqlite3.OperationalError as e:
                            logger.debug(f"[Location] sync_item query failed: {e}")

                    # CachedGeoposition.db (WebView)
                    if "CachedPosition" in tables:
                        try:
                            cursor.execute("""
                                SELECT latitude, longitude, accuracy, timestamp
                                FROM CachedPosition ORDER BY timestamp ASC
                            """)
                            for row in cursor.fetchall():
                                ts = self.normalize_timestamp(row["timestamp"])
                                artifacts.append(Artifact(
                                    artifact_id=f"loc_geo_{ts}",
                                    artifact_type="LOCATION",
                                    source_path=db_path,
                                    timestamp_utc=ts,
                                    parser_name=self.NAME,
                                    parser_version=self.VERSION,
                                    actor="DEVICE",
                                    details={
                                        "latitude": row["latitude"],
                                        "longitude": row["longitude"],
                                        "accuracy_m": row["accuracy"],
                                        "provider": "WEBVIEW_GEO",
                                    },
                                ))
                        except sqlite3.OperationalError as e:
                            logger.debug(f"[Location] CachedPosition query failed: {e}")

                    conn.close()
            except Exception as e:
                logger.warning(f"[Location] Failed to process {db_path}: {e}")

        # ── JSON location files ───────────────────────────────────────────────
        for json_path in json_candidates:
            try:
                raw = vfs.read_bytes(json_path)
                data = json.loads(raw.decode("utf-8", errors="replace"))

                # Google Takeout Location History format
                locations = []
                if isinstance(data, dict):
                    locations = data.get("locations", data.get("timelineObjects", []))
                elif isinstance(data, list):
                    locations = data

                for loc in locations[:10000]:  # Cap at 10k to avoid resource exhaustion
                    if isinstance(loc, dict):
                        lat = loc.get("latitudeE7", loc.get("latitude"))
                        lng = loc.get("longitudeE7", loc.get("longitude"))
                        ts_str = loc.get("timestampMs", loc.get("timestamp", "0"))

                        if lat is not None and lng is not None:
                            # E7 format: divide by 1e7
                            if isinstance(lat, int) and abs(lat) > 1_000_000:
                                lat = lat / 1e7
                                lng = lng / 1e7

                            ts = self.normalize_timestamp(ts_str)

                            artifacts.append(Artifact(
                                artifact_id=f"loc_json_{ts}_{abs(hash((lat, lng)))}",
                                artifact_type="LOCATION",
                                source_path=json_path,
                                timestamp_utc=ts,
                                parser_name=self.NAME,
                                parser_version=self.VERSION,
                                actor="DEVICE",
                                details={
                                    "latitude": lat,
                                    "longitude": lng,
                                    "accuracy_m": loc.get("accuracy", ""),
                                    "provider": "GOOGLE_LOCATION_HISTORY",
                                },
                            ))
            except Exception as e:
                logger.warning(f"[Location] Failed to parse JSON {json_path}: {e}")

        return artifacts
