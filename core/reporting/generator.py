"""
XtractR Report Generator — Professional SaaS Dashboard
Queries all artifact data from case.db and produces a self-contained report.html.
"""
import os
import json
import logging
from datetime import datetime
from ..database import CaseDatabase
from ..integrity import compute_merkle_root
from .template import CSS, JS, GOOGLE_FONTS, nav_item, page_header, table_start, table_end, badge

logger = logging.getLogger("xtractr.reporting")


def generate_report(db: CaseDatabase, output_dir: str) -> str:
    logger.info("Generating Professional Forensic Report...")

    def get_count(table):
        c = db._conn.cursor()
        c.execute(f"SELECT COUNT(*) FROM {table}")
        return c.fetchone()[0]

    def safe_parse(d):
        try:
            if isinstance(d, dict): return d
            return json.loads(d) if d else {}
        except Exception:
            return {"_raw": str(d)}

    def ts_fmt(ts_ms):
        if not ts_ms or ts_ms <= 0: return "—"
        try: return datetime.utcfromtimestamp(ts_ms / 1000).strftime("%Y-%m-%d %H:%M:%S")
        except Exception: return str(ts_ms)

    def esc(s):
        if s is None: return ""
        return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

    def td(v, cls=""): return f'<td class="{cls}">{v}</td>' if cls else f'<td>{v}</td>'
    def td_mono(v): return td(esc(str(v)), "mono")

    # ── Data queries ──────────────────────────────────────────────
    case_id = db.get_metadata("case_id") or "UNKNOWN"
    investigator = db.get_metadata("investigator_name") or "Unknown"
    gen_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    total_artifacts = get_count("derived_artifacts")
    total_events = get_count("custody_events")
    total_baseline = get_count("baseline_files")

    c = db._conn.cursor()

    def fetch_by_type(atype, order="timestamp_utc ASC"):
        c.execute(f"SELECT timestamp_utc, actor, details, source_path FROM derived_artifacts WHERE artifact_type=? ORDER BY {order}", (atype,))
        return c.fetchall()

    def fetch_by_types(atypes, order="timestamp_utc ASC"):
        ph = ",".join("?" * len(atypes))
        c.execute(f"SELECT timestamp_utc, actor, details, source_path FROM derived_artifacts WHERE artifact_type IN ({ph}) ORDER BY {order}", atypes)
        return c.fetchall()

    sms_rows = fetch_by_types(["SMS", "MMS"])
    call_rows = fetch_by_type("CALL_LOG")
    contact_rows = fetch_by_type("CONTACT", "actor ASC")
    web_rows = fetch_by_types(["WEB_HISTORY", "WEB_DOWNLOAD"], "timestamp_utc DESC")
    media_rows = fetch_by_type("MEDIA", "timestamp_utc DESC")
    app_rows = fetch_by_type("INSTALLED_APP", "details ASC")
    wa_rows = fetch_by_type("WHATSAPP_MSG")
    tg_rows = fetch_by_types(["TELEGRAM_MSG", "TELEGRAM_CONTACT", "TELEGRAM_MEDIA"])
    ig_rows = fetch_by_types(["INSTAGRAM_MSG", "INSTAGRAM_THREAD"])
    email_rows = fetch_by_types(["EMAIL", "EMAIL_THREAD"])
    loc_rows = fetch_by_types(["LOCATION", "SAVED_PLACE"])
    account_rows = fetch_by_type("ACCOUNT", "actor ASC")

    c.execute("SELECT timestamp_utc, artifact_type, actor, details, source_path, plugin_name FROM derived_artifacts WHERE timestamp_utc > 0 ORDER BY timestamp_utc ASC")
    timeline_rows = c.fetchall()

    c.execute("SELECT * FROM custody_events ORDER BY id ASC")
    ledger_rows = c.fetchall()

    c.execute("SELECT artifact_type, COUNT(*) as cnt FROM derived_artifacts GROUP BY artifact_type ORDER BY cnt DESC")
    stats_rows = c.fetchall()

    # ── Build table HTML ──────────────────────────────────────────
    def build_sms():
        h = table_start("sms-table", ["Timestamp", "Contact", "Direction", "Body", "Read"])
        for r in sms_rows:
            d = safe_parse(r["details"])
            direction = d.get("direction", "N/A")
            h += f'<tr>{td(ts_fmt(r["timestamp_utc"]))}{td(esc(r["actor"]))}{td(badge(direction))}<td class="wrap">{esc(str(d.get("body",""))[:300])}</td>{td("✓" if d.get("read") else "✗")}</tr>'
        return h + table_end("sms")

    def build_calls():
        h = table_start("calls-table", ["Timestamp", "Number", "Type", "Duration"])
        for r in call_rows:
            d = safe_parse(r["details"])
            ctype = d.get("type", "UNKNOWN")
            h += f'<tr>{td(ts_fmt(r["timestamp_utc"]))}{td_mono(r["actor"])}{td(badge(ctype))}{td(str(d.get("duration_sec",0))+"s")}</tr>'
        return h + table_end("calls")

    def build_contacts():
        h = table_start("contacts-table", ["Name", "Number", "Source"])
        for r in contact_rows:
            d = safe_parse(r["details"])
            h += f'<tr>{td(esc(d.get("name","N/A")))}{td_mono(d.get("number", r["actor"]))}{td_mono(r["source_path"])}</tr>'
        return h + table_end("contacts")

    def build_web():
        h = table_start("web-table", ["Timestamp", "URL", "Title", "Visits"])
        for r in web_rows:
            d = safe_parse(r["details"])
            h += f'<tr>{td(ts_fmt(r["timestamp_utc"]))}<td class="mono wrap">{esc(str(d.get("url",""))[:120])}</td>{td(esc(d.get("title","")))}{td(str(d.get("visit_count","")))}</tr>'
        return h + table_end("web")

    def build_media():
        h = table_start("media-table", ["Filename", "Extension", "Size", "Modified", "GPS"])
        for r in media_rows:
            d = safe_parse(r["details"])
            gps = d.get("gps", {})
            gps_str = ""
            if gps.get("latitude_decimal"):
                gps_str = f'{gps["latitude_decimal"]}, {gps.get("longitude_decimal","")}'
            sz = d.get("size_bytes", d.get("size", 0))
            sz_str = f'{sz:,}' if isinstance(sz, int) else str(sz)
            h += f'<tr>{td(esc(d.get("filename","")))}{td_mono(d.get("extension",""))}{td(sz_str)}{td(ts_fmt(r["timestamp_utc"]))}{td_mono(gps_str)}</tr>'
        return h + table_end("media")

    def build_apps():
        h = table_start("apps-table", ["Package", "Version", "UID / Path", "Install", "Updated"])
        for r in app_rows:
            d = safe_parse(r["details"])
            h += f'<tr>{td_mono(d.get("package",""))}{td(esc(d.get("version","")))}{td_mono(d.get("uid", d.get("path","")))}{td(esc(d.get("first_install","")))}{td(esc(d.get("last_update","")))}</tr>'
        return h + table_end("apps")

    def build_whatsapp():
        h = table_start("wa-table", ["Timestamp", "Chat", "Direction", "Media", "Body"])
        for r in wa_rows:
            d = safe_parse(r["details"])
            h += f'<tr>{td(ts_fmt(r["timestamp_utc"]))}{td(esc(r["actor"]))}{td(badge(d.get("direction","N/A")))}{td(badge(d.get("media_type","TEXT"), d.get("media_type","text").lower()))}<td class="wrap">{esc(str(d.get("body",""))[:200])}</td></tr>'
        return h + table_end("wa")

    def build_telegram():
        h = table_start("tg-table", ["Timestamp", "UID", "Direction", "Body"])
        for r in tg_rows:
            d = safe_parse(r["details"])
            h += f'<tr>{td(ts_fmt(r["timestamp_utc"]))}{td_mono(r["actor"])}{td(badge(d.get("direction", "N/A")))}<td class="wrap">{esc(str(d.get("body",""))[:200])}</td></tr>'
        return h + table_end("tg")

    def build_instagram():
        h = table_start("ig-table", ["Timestamp", "User", "Type", "Body"])
        for r in ig_rows:
            d = safe_parse(r["details"])
            h += f'<tr>{td(ts_fmt(r["timestamp_utc"]))}{td(esc(r["actor"]))}{td(badge(d.get("message_type","TEXT")))}<td class="wrap">{esc(str(d.get("body", d.get("title","")))[:200])}</td></tr>'
        return h + table_end("ig")

    def build_email():
        h = table_start("email-table", ["Timestamp", "From", "To", "Subject", "Snippet"])
        for r in email_rows:
            d = safe_parse(r["details"])
            h += f'<tr>{td(ts_fmt(r["timestamp_utc"]))}{td(esc(d.get("from", r["actor"])))}{td(esc(d.get("to","")))}{td(esc(d.get("subject","")))}<td class="wrap">{esc(str(d.get("snippet", d.get("body_snippet","")))[:150])}</td></tr>'
        return h + table_end("email")

    def build_location():
        h = table_start("loc-table", ["Timestamp", "Latitude", "Longitude", "Accuracy", "Provider"])
        for r in loc_rows:
            d = safe_parse(r["details"])
            lat = d.get("latitude", d.get("latitude_decimal", ""))
            lon = d.get("longitude", d.get("longitude_decimal", ""))
            h += f'<tr>{td(ts_fmt(r["timestamp_utc"]))}{td_mono(str(lat))}{td_mono(str(lon))}{td(str(d.get("accuracy_m","")))}{td(badge(d.get("provider","UNKNOWN"),"type"))}</tr>'
        return h + table_end("loc")

    def build_accounts():
        h = table_start("accounts-table", ["Account", "Type", "Source"])
        for r in account_rows:
            d = safe_parse(r["details"])
            h += f'<tr>{td(esc(d.get("account_name", r["actor"])))}{td(esc(d.get("account_type","N/A")))}{td_mono(r["source_path"])}</tr>'
        return h + table_end("accounts")

    def build_timeline():
        h = table_start("timeline-table", ["Timestamp", "Type", "Actor", "Summary", "Parser"])
        for r in timeline_rows:
            d = safe_parse(r["details"])
            atype = r["artifact_type"]
            summary = ""
            if atype == "SMS": summary = esc(str(d.get("body",""))[:120])
            elif atype == "CALL_LOG": summary = f'{d.get("type","CALL")} — {d.get("duration_sec",0)}s'
            elif atype == "WEB_HISTORY": summary = esc(str(d.get("url",""))[:120])
            elif atype == "MEDIA": summary = esc(d.get("filename",""))
            elif atype == "WHATSAPP_MSG": summary = esc(str(d.get("body",""))[:120])
            elif atype == "EMAIL": summary = esc(d.get("subject",""))
            elif atype == "LOCATION": summary = f'{d.get("latitude","")}, {d.get("longitude","")}'
            else: summary = esc(str(d)[:100])
            h += f'<tr>{td(ts_fmt(r["timestamp_utc"]))}{td(badge(atype, "type"))}{td(esc(r["actor"]))}<td class="wrap">{summary}</td>{td(esc(r["plugin_name"]))}</tr>'
        return h + table_end("timeline")

    def build_ledger():
        h = table_start("ledger-table", ["ID", "Timestamp", "Action", "Details", "Hash"])
        for r in ledger_rows:
            h += f'<tr>{td(str(r["id"]))}{td(ts_fmt(r["timestamp_utc"]))}{td(esc(r["action"]))}<td class="wrap">{esc(str(r["details"])[:200])}</td>{td_mono(str(r["this_event_hash"])[:32]+"…")}</tr>'
        return h + table_end("ledger")

    def build_stats():
        h = table_start("stats-table", ["Artifact Type", "Count"])
        for r in stats_rows:
            h += f'<tr>{td(badge(r[0], "type"))}{td(str(r[1]))}</tr>'
        return h + table_end("stats")

    # ── Overview page ─────────────────────────────────────────────
    overview_html = f'''
    <div class="stats-row">
      <div class="stat-card"><div class="stat-value">{total_artifacts:,}</div><div class="stat-name">Total Artifacts</div></div>
      <div class="stat-card"><div class="stat-value">{len(sms_rows):,}</div><div class="stat-name">SMS / MMS</div></div>
      <div class="stat-card"><div class="stat-value">{len(call_rows):,}</div><div class="stat-name">Call Logs</div></div>
      <div class="stat-card"><div class="stat-value">{len(contact_rows):,}</div><div class="stat-name">Contacts</div></div>
      <div class="stat-card"><div class="stat-value">{len(web_rows):,}</div><div class="stat-name">Web History</div></div>
      <div class="stat-card"><div class="stat-value">{len(media_rows):,}</div><div class="stat-name">Media Files</div></div>
      <div class="stat-card"><div class="stat-value">{len(app_rows):,}</div><div class="stat-name">Apps</div></div>
      <div class="stat-card"><div class="stat-value">{len(wa_rows):,}</div><div class="stat-name">WhatsApp</div></div>
      <div class="stat-card"><div class="stat-value">{len(tg_rows):,}</div><div class="stat-name">Telegram</div></div>
      <div class="stat-card"><div class="stat-value">{len(ig_rows):,}</div><div class="stat-name">Instagram</div></div>
      <div class="stat-card"><div class="stat-value">{len(email_rows):,}</div><div class="stat-name">Email</div></div>
      <div class="stat-card"><div class="stat-value">{len(loc_rows):,}</div><div class="stat-name">Location</div></div>
      <div class="stat-card"><div class="stat-value">{total_baseline:,}</div><div class="stat-name">Files Baselined</div></div>
      <div class="stat-card"><div class="stat-value">{total_events:,}</div><div class="stat-name">Custody Events</div></div>
    </div>
    <div class="integrity-banner">
      <div style="font-weight:600;margin-bottom:10px;font-size:14px;">Integrity Summary</div>
      <div class="integrity-row"><div class="integrity-dot ok"></div><span class="integrity-label">Evidence sealed with Merkle tree</span></div>
      <div class="integrity-row"><div class="integrity-dot ok"></div><span class="integrity-label">Chain of custody: {total_events} events</span></div>
      <div class="integrity-row"><div class="integrity-dot ok"></div><span class="integrity-label">Baseline files hashed: {total_baseline}</span></div>
      <div class="integrity-row"><div class="integrity-dot ok"></div><span class="integrity-label">Verify with: <code style="font-family:var(--font-mono);background:var(--bg-elevated);padding:2px 6px;border-radius:3px;font-size:12px;">xtractr_verify.py verify &lt;bundle_dir&gt;</code></span></div>
    </div>
    '''

    # ── Assemble HTML ─────────────────────────────────────────────
    sidebar_html = f'''
    <div class="sidebar-label">Investigation</div>
    <div class="sidebar-section">
      {nav_item("overview", "Overview")}
      {nav_item("sms", "SMS", len(sms_rows))}
      {nav_item("calls", "Calls", len(call_rows))}
      {nav_item("contacts", "Contacts", len(contact_rows))}
      {nav_item("web", "Web", len(web_rows))}
      {nav_item("media", "Media", len(media_rows))}
      {nav_item("apps", "Apps", len(app_rows))}
    </div>
    <div class="sidebar-label">Messaging</div>
    <div class="sidebar-section">
      {nav_item("wa", "WhatsApp", len(wa_rows))}
      {nav_item("tg", "Telegram", len(tg_rows))}
      {nav_item("ig", "Instagram", len(ig_rows))}
      {nav_item("email", "Email", len(email_rows))}
    </div>
    <div class="sidebar-label">Analysis</div>
    <div class="sidebar-section">
      {nav_item("loc", "Location", len(loc_rows))}
      {nav_item("accounts", "Accounts", len(account_rows))}
      {nav_item("timeline", "Timeline", len(timeline_rows))}
    </div>
    <div class="sidebar-label">Governance</div>
    <div class="sidebar-section">
      {nav_item("ledger", "Ledger", len(ledger_rows))}
      {nav_item("stats", "Statistics", len(stats_rows))}
    </div>
    '''

    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>XtractR Report — {esc(case_id)}</title>
<meta name="description" content="Forensic evidence report for case {esc(case_id)}">
{GOOGLE_FONTS}
<style>{CSS}</style>
</head>
<body>

<nav class="topbar" role="banner">
  <div class="topbar-logo">
    <svg viewBox="0 0 20 20" fill="currentColor"><path d="M10 2L2 7v6l8 5 8-5V7l-8-5zm0 2.24L15.5 7.5 10 10.76 4.5 7.5 10 4.24zM4 8.88l5 3.12v4.76l-5-3.12V8.88zm12 0v4.76l-5 3.12V12l5-3.12z"/></svg>
    XTRACTR
  </div>
  <div class="topbar-sep"></div>
  <div class="topbar-case">{esc(case_id)}</div>
  <div class="topbar-meta">{gen_time}</div>
  <div class="topbar-spacer"></div>
  <div class="topbar-inv">{esc(investigator)}</div>
  <button class="topbar-btn" onclick="window.print()">Print Report</button>
</nav>

<aside class="sidebar" role="navigation" aria-label="Evidence navigation">{sidebar_html}</aside>

<main class="main">
  <div class="page active" id="page-overview">
    <div class="page-header"><div class="page-title">Case Overview</div>
    <div class="page-subtitle">Case {esc(case_id)} — {esc(investigator)} — {gen_time}</div></div>
    {overview_html}
  </div>

  <div class="page" id="page-sms">{page_header("SMS Messages", len(sms_rows), "sms-table")}{build_sms()}</div>
  <div class="page" id="page-calls">{page_header("Call Logs", len(call_rows), "calls-table")}{build_calls()}</div>
  <div class="page" id="page-contacts">{page_header("Contacts", len(contact_rows), "contacts-table")}{build_contacts()}</div>
  <div class="page" id="page-web">{page_header("Web History", len(web_rows), "web-table")}{build_web()}</div>
  <div class="page" id="page-media">{page_header("Media Files", len(media_rows), "media-table")}{build_media()}</div>
  <div class="page" id="page-apps">{page_header("Installed Apps", len(app_rows), "apps-table")}{build_apps()}</div>
  <div class="page" id="page-wa">{page_header("WhatsApp Messages", len(wa_rows), "wa-table")}{build_whatsapp()}</div>
  <div class="page" id="page-tg">{page_header("Telegram", len(tg_rows), "tg-table")}{build_telegram()}</div>
  <div class="page" id="page-ig">{page_header("Instagram", len(ig_rows), "ig-table")}{build_instagram()}</div>
  <div class="page" id="page-email">{page_header("Email", len(email_rows), "email-table")}{build_email()}</div>
  <div class="page" id="page-loc">{page_header("Location Data", len(loc_rows), "loc-table")}{build_location()}</div>
  <div class="page" id="page-accounts">{page_header("Accounts", len(account_rows), "accounts-table")}{build_accounts()}</div>
  <div class="page" id="page-timeline">{page_header("Timeline", len(timeline_rows), "timeline-table")}{build_timeline()}</div>
  <div class="page" id="page-ledger">{page_header("Evidence Ledger", len(ledger_rows), "ledger-table")}{build_ledger()}</div>
  <div class="page" id="page-stats">{page_header("Statistics", len(stats_rows), "stats-table")}{build_stats()}</div>

  <div class="footer">Generated by XtractR Core v1.1.0 · Verify with <code>xtractr_verify.py</code> · Cryptographically Sealed</div>
</main>

<script>{JS}
showSection('overview');
</script>
</body>
</html>'''

    report_path = os.path.join(output_dir, "report.html")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html)

    logger.info(f"Report generated: {report_path}")
    return report_path
