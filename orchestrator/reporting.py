import os
import datetime
from .signing import load_keys, sign_data

class ReportGenerator:
    def __init__(self, case_dir, case_id, investigator_name):
        self.case_dir = case_dir
        self.case_id = case_id
        self.investigator_name = investigator_name
        self.report_dir = os.path.join(case_dir, "reports")
        os.makedirs(self.report_dir, exist_ok=True)

    def generate_html_report(self, merkle_root, drift_stats, custody_events, inv_profile=None):
        """Generate a simple HTML forensic report."""
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        
        if inv_profile:
            p_name, p_id, p_org, p_desig, p_loc = inv_profile[1], inv_profile[2], inv_profile[3], inv_profile[4], inv_profile[6]
        else:
            p_name, p_id, p_org, p_desig, p_loc = self.investigator_name, "N/A", "N/A", "N/A", "N/A"
            
        rows = ""
        for event in custody_events:
            rows += f"<tr><td>{event[1]}</td><td>{event[3]}</td><td>{event[8]}</td><td>{event[7][:16]}...</td></tr>"
            
        html = f"""
<html>
<head>
    <title>Forensic Report - {self.case_id}</title>
    <style>
        body {{ font-family: sans-serif; padding: 20px; }}
        h1 {{ color: #2c3e50; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .alert {{ color: red; font-weight: bold; }}
        .metadata {{ background: #f9f9f9; padding: 15px; border-radius: 5px; }}
    </style>
</head>
<body>
    <h1>XtractR Forensic Report</h1>
    <div class="metadata">
        <p><strong>Case ID:</strong> {self.case_id}</p>
        <p><strong>Generated:</strong> {timestamp}</p>
        <p><strong>Investigator:</strong> {p_name} ({p_id})</p>
        <p><strong>Organization:</strong> {p_org}, {p_desig}</p>
        <p><strong>Location:</strong> {p_loc}</p>
        <p><strong>Merkle Root Seal:</strong> {merkle_root}</p>
    </div>
    
    <h2>Evidence Drift Status</h2>
    <p class="alert">{drift_stats}</p>
    
    <h2>Chain of Custody Ledger</h2>
    <table>
        <tr><th>Timestamp</th><th>Action</th><th>Notes</th><th>Event Hash</th></tr>
        {rows}
    </table>
</body>
</html>
        """
        
        report_path = os.path.join(self.report_dir, "report.html")
        with open(report_path, "w") as f:
            f.write(html.strip())
            
        return report_path, html

    def sign_report(self, key_dir):
        """Sign the main report artifacts."""
        file_to_sign = os.path.join(self.report_dir, "report.html")
        if not os.path.exists(file_to_sign):
            return None
            
        private_key, _ = load_keys(key_dir)
        
        with open(file_to_sign, "rb") as f:
            data = f.read()
            
        signature = sign_data(private_key, data)
        
        sig_path = os.path.join(self.report_dir, "report.sig")
        with open(sig_path, "wb") as f:
            f.write(signature)
            
        return sig_path
