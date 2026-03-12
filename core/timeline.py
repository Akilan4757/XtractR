import json
import csv
import logging
import os
from typing import List, Dict, Any
from .database import CaseDatabase

logger = logging.getLogger("xtractr.timeline")

class TimelineEngine:
    def __init__(self, db: CaseDatabase, output_dir: str):
        self.db = db
        self.output_dir = output_dir

    def build_timeline(self) -> str:
        """
        Generates timeline artifacts (JSON, CSV).
        Returns path to timeline.json.
        """
        logger.info("Building Unified Timeline...")
        
        cursor = self.db._conn.cursor()
        cursor.execute("""
            SELECT timestamp_utc, artifact_type, actor, details, source_path, plugin_name 
            FROM derived_artifacts 
            ORDER BY timestamp_utc ASC
        """)
        
        events = []
        rows = cursor.fetchall()
        
        for row in rows:
            # Parse details from JSON string (INV-003: never use eval())
            try:
                details = json.loads(row["details"])
            except (json.JSONDecodeError, TypeError):
                details = {"_raw": str(row["details"])}

            events.append({
                "timestamp": row["timestamp_utc"],
                "type": row["artifact_type"],
                "actor": row["actor"],
                "details": details,
                "source": row["source_path"],
                "plugin": row["plugin_name"]
            })
        
        # INV-002: Deterministic sort with full tiebreaker chain
        events.sort(key=lambda e: (
            e["timestamp"],
            e["type"],
            e["source"],
            e["actor"]
        ))
        
        # Write JSON
        json_path = os.path.join(self.output_dir, "timeline.json")
        with open(json_path, "w") as f:
            json.dump(events, f, indent=2, sort_keys=True)
            
        # Write CSV
        csv_path = os.path.join(self.output_dir, "timeline.csv")
        try:
            with open(csv_path, "w", newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["Timestamp (UTC)", "Type", "Actor", "Details", "Source", "Plugin"])
                for e in events:
                    writer.writerow([
                        e["timestamp"],
                        e["type"],
                        e["actor"],
                        str(e["details"])[:500], # Trucate for CSV
                        e["source"],
                        e["plugin"]
                    ])
        except Exception as e:
            logger.error(f"Failed to write CSV timeline: {e}")
            
        return json_path
