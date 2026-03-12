import logging
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
        # SQLite doesn't have easy timestamp functions on int epoch without extensions sometimes
        # We'll fetch timestamps and process in python for MVP
        cursor.execute("SELECT timestamp_utc FROM derived_artifacts WHERE timestamp_utc > 0")
        rows = cursor.fetchall()
        
        heatmap = {h: 0 for h in range(24)}
        for r in rows:
            ts = r["timestamp_utc"] / 1000
            import datetime
            dt = datetime.datetime.utcfromtimestamp(ts)
            heatmap[dt.hour] += 1
            
        results["activity_heatmap"] = heatmap
        
        return results
