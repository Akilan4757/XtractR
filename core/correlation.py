import logging
import datetime
from typing import List, Dict, Any
from .database import CaseDatabase

logger = logging.getLogger("xtractr.correlation")

class CorrelationEngine:
    def __init__(self, db: CaseDatabase):
        self.db = db

    def run_correlations(self) -> Dict[str, Any]:
        """
        Analyze artifacts for patterns.
        """
        logger.info("Running Correlation Analysis...")
        results = {
            "top_actors": [],
            "activity_heatmap": {},
            "suspicious_gaps": []
        }
        
        cursor = self.db._conn.cursor()
        
        # 1. Top Actors (Communicators)
        cursor.execute("""
            SELECT actor, COUNT(*) as count 
            FROM derived_artifacts 
            WHERE artifact_type IN ('SMS', 'CALL_LOG', 'CONTACT') AND actor != 'DEVICE'
            GROUP BY actor 
            ORDER BY count DESC 
            LIMIT 10
        """)
        results["top_actors"] = [{"actor": r[0], "count": r[1]} for r in cursor.fetchall()]
        
        # 2. Activity Heatmap (Hour of Day)
        cursor.execute("SELECT timestamp_utc FROM derived_artifacts WHERE timestamp_utc > 0")
        rows = cursor.fetchall()
        
        heatmap = {h: 0 for h in range(24)}
        for r in rows:
            ts = r["timestamp_utc"] / 1000
            dt = datetime.datetime.utcfromtimestamp(ts)
            heatmap[dt.hour] += 1
            
        results["activity_heatmap"] = heatmap
        
        # 3. Suspicious Gaps (Timeline Inactivity > 6 hours)
        cursor.execute("""
            SELECT timestamp_utc, artifact_type 
            FROM derived_artifacts 
            WHERE timestamp_utc > 0 
            ORDER BY timestamp_utc ASC
        """)
        timeline_rows = cursor.fetchall()
        
        gaps = []
        six_hours_ms = 6 * 60 * 60 * 1000
        for i in range(len(timeline_rows) - 1):
            t1 = timeline_rows[i]["timestamp_utc"]
            t2 = timeline_rows[i+1]["timestamp_utc"]
            diff = t2 - t1
            if diff > six_hours_ms:
                dt1 = datetime.datetime.utcfromtimestamp(t1 / 1000).isoformat() + "Z"
                dt2 = datetime.datetime.utcfromtimestamp(t2 / 1000).isoformat() + "Z"
                gaps.append({
                    "start_timestamp": t1,
                    "end_timestamp": t2,
                    "start_utc": dt1,
                    "end_utc": dt2,
                    "gap_duration_seconds": int(diff / 1000)
                })
        results["suspicious_gaps"] = gaps
        
        return results
