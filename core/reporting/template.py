"""
XtractR Report Template — Professional SaaS Dashboard
CSS, HTML structure, and JS for the forensic evidence report.
"""

GOOGLE_FONTS = '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap">'

CSS = """
:root {
  --bg-primary: #0d1117; --bg-surface: #161b22; --bg-elevated: #1c2128;
  --border: #30363d; --border-light: #21262d;
  --text-primary: #e6edf3; --text-secondary: #8b949e; --text-muted: #484f58;
  --accent: #58a6ff; --accent-hover: #79c0ff;
  --green: #3fb950; --red: #f85149; --orange: #d29922; --purple: #bc8cff;
  --sidebar-w: 220px; --topbar-h: 56px;
  --font-ui: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
  --font-mono: 'JetBrains Mono', 'SF Mono', 'Cascadia Code', monospace;
  --row-h: 36px; --radius: 6px;
}
*, *::before, *::after { margin:0; padding:0; box-sizing:border-box; }
html { font-size: 14px; }
body { font-family: var(--font-ui); background: var(--bg-primary); color: var(--text-primary);
  line-height: 1.5; -webkit-font-smoothing: antialiased; overflow-x: hidden; }

/* === TOP NAV === */
.topbar { position:fixed; top:0; left:0; right:0; height:var(--topbar-h); z-index:100;
  background:var(--bg-surface); border-bottom:1px solid var(--border);
  display:flex; align-items:center; padding:0 24px; gap:16px; }
.topbar-logo { font-weight:700; font-size:15px; color:var(--accent); letter-spacing:-0.02em;
  display:flex; align-items:center; gap:8px; }
.topbar-logo svg { width:20px; height:20px; }
.topbar-sep { width:1px; height:24px; background:var(--border); }
.topbar-case { font-family:var(--font-mono); font-size:12px; color:var(--text-secondary);
  background:var(--bg-elevated); padding:4px 10px; border-radius:4px; border:1px solid var(--border); }
.topbar-meta { font-size:12px; color:var(--text-muted); }
.topbar-spacer { flex:1; }
.topbar-inv { font-size:12px; color:var(--text-secondary); }
.topbar-btn { padding:6px 14px; background:var(--bg-elevated); border:1px solid var(--border);
  border-radius:var(--radius); color:var(--text-secondary); cursor:pointer; font-size:12px;
  font-family:var(--font-ui); font-weight:500; transition:all .15s; }
.topbar-btn:hover { background:var(--accent); color:#fff; border-color:var(--accent); }

/* === SIDEBAR === */
.sidebar { position:fixed; top:var(--topbar-h); left:0; bottom:0; width:var(--sidebar-w);
  background:var(--bg-surface); border-right:1px solid var(--border); z-index:90;
  overflow-y:auto; padding:12px 0; }
.sidebar::-webkit-scrollbar { width:4px; }
.sidebar::-webkit-scrollbar-thumb { background:var(--border); border-radius:2px; }
.sidebar-section { padding:0 12px; margin-bottom:4px; }
.sidebar-label { font-size:10px; text-transform:uppercase; letter-spacing:.8px;
  color:var(--text-muted); padding:8px 12px 4px; font-weight:600; }
.nav-item { display:flex; align-items:center; justify-content:space-between;
  padding:7px 12px; border-radius:var(--radius); cursor:pointer;
  color:var(--text-secondary); font-size:13px; font-weight:500;
  transition:all .12s; user-select:none; }
.nav-item:hover { background:var(--bg-elevated); color:var(--text-primary); }
.nav-item.active { background:rgba(88,166,255,.1); color:var(--accent); }
.nav-item:focus-visible { outline:2px solid var(--accent); outline-offset:-2px; }
.nav-badge { font-size:11px; font-family:var(--font-mono); color:var(--text-muted);
  background:var(--bg-elevated); padding:1px 7px; border-radius:10px; min-width:24px;
  text-align:center; font-weight:500; }
.nav-item.active .nav-badge { background:rgba(88,166,255,.15); color:var(--accent); }
.nav-icon { width:16px; height:16px; margin-right:8px; opacity:.6; flex-shrink:0; }
.nav-item.active .nav-icon { opacity:1; }

/* === MAIN === */
.main { margin-left:var(--sidebar-w); margin-top:var(--topbar-h); min-height:calc(100vh - var(--topbar-h)); }
.page { display:none; padding:24px; }
.page.active { display:block; }

/* === PAGE HEADER === */
.page-header { margin-bottom:20px; }
.page-title { font-size:20px; font-weight:700; letter-spacing:-0.02em; color:var(--text-primary); }
.page-subtitle { font-size:13px; color:var(--text-muted); margin-top:2px; }
.page-toolbar { display:flex; align-items:center; gap:10px; margin-top:14px; flex-wrap:wrap; }
.search-input { width:280px; padding:7px 12px; background:var(--bg-surface); border:1px solid var(--border);
  border-radius:var(--radius); color:var(--text-primary); font-size:13px; font-family:var(--font-ui);
  outline:none; transition:border-color .15s; }
.search-input::placeholder { color:var(--text-muted); }
.search-input:focus { border-color:var(--accent); }
.toolbar-spacer { flex:1; }
.count-label { font-size:12px; color:var(--text-muted); font-family:var(--font-mono); }

/* === OVERVIEW CARDS === */
.stats-row { display:grid; grid-template-columns:repeat(auto-fill,minmax(160px,1fr)); gap:12px; margin-bottom:24px; }
.stat-card { background:var(--bg-surface); border:1px solid var(--border); border-radius:var(--radius);
  padding:16px 18px; }
.stat-value { font-size:28px; font-weight:700; letter-spacing:-0.03em; color:var(--text-primary);
  font-family:var(--font-mono); line-height:1.1; }
.stat-name { font-size:11px; text-transform:uppercase; letter-spacing:.5px; color:var(--text-muted);
  margin-top:6px; font-weight:600; }

/* === TABLES === */
.table-container { background:var(--bg-surface); border:1px solid var(--border);
  border-radius:var(--radius); overflow:hidden; }
.table-scroll { overflow-x:auto; max-height:calc(100vh - 260px); overflow-y:auto; }
table { width:100%; border-collapse:collapse; font-size:13px; }
thead { position:sticky; top:0; z-index:5; }
th { background:var(--bg-elevated); color:var(--text-muted); font-weight:600;
  text-transform:uppercase; font-size:10.5px; letter-spacing:.6px;
  padding:0 14px; height:var(--row-h); text-align:left; white-space:nowrap;
  border-bottom:1px solid var(--border); cursor:pointer; user-select:none; }
th:hover { color:var(--text-secondary); }
th .sort-arrow { font-size:10px; margin-left:4px; opacity:.4; }
th.sorted .sort-arrow { opacity:1; color:var(--accent); }
td { padding:0 14px; height:var(--row-h); vertical-align:middle;
  border-top:1px solid var(--border-light); color:var(--text-secondary);
  white-space:nowrap; overflow:hidden; text-overflow:ellipsis; max-width:400px; }
tr:hover td { background:var(--bg-elevated); }
td.wrap { white-space:normal; word-break:break-word; }
td.mono { font-family:var(--font-mono); font-size:11.5px; color:var(--text-muted); }

/* === BADGES === */
.badge { display:inline-block; padding:2px 8px; border-radius:4px; font-size:10.5px;
  font-weight:600; text-transform:uppercase; letter-spacing:.3px; }
.badge-sent { background:rgba(88,166,255,.12); color:var(--accent); }
.badge-recv,.badge-received { background:rgba(63,185,80,.12); color:var(--green); }
.badge-incoming { background:rgba(63,185,80,.12); color:var(--green); }
.badge-outgoing { background:rgba(88,166,255,.12); color:var(--accent); }
.badge-missed { background:rgba(248,81,73,.12); color:var(--red); }
.badge-rejected,.badge-blocked { background:rgba(248,81,73,.12); color:var(--red); }
.badge-voicemail { background:rgba(210,153,34,.12); color:var(--orange); }
.badge-unknown { background:rgba(72,79,88,.2); color:var(--text-muted); }
.badge-type { background:rgba(188,140,255,.1); color:var(--purple); }
.badge-text { background:rgba(88,166,255,.08); color:var(--accent); }
.badge-image,.badge-photo { background:rgba(63,185,80,.1); color:var(--green); }
.badge-video { background:rgba(210,153,34,.1); color:var(--orange); }
.badge-audio,.badge-voice { background:rgba(188,140,255,.1); color:var(--purple); }
.badge-document { background:rgba(72,79,88,.2); color:var(--text-secondary); }

/* === PAGINATION === */
.pagination { display:flex; align-items:center; justify-content:space-between; padding:10px 14px;
  border-top:1px solid var(--border); font-size:12px; color:var(--text-muted); }
.pagination button { padding:5px 12px; background:var(--bg-elevated); border:1px solid var(--border);
  border-radius:var(--radius); color:var(--text-secondary); cursor:pointer; font-size:12px;
  font-family:var(--font-ui); transition:all .15s; }
.pagination button:hover:not(:disabled) { border-color:var(--accent); color:var(--accent); }
.pagination button:disabled { opacity:.3; cursor:default; }
.page-info { font-family:var(--font-mono); }

/* === INTEGRITY BANNER === */
.integrity-banner { background:var(--bg-surface); border:1px solid var(--border);
  border-radius:var(--radius); padding:16px 20px; margin-bottom:24px; }
.integrity-row { display:flex; align-items:center; gap:8px; margin-bottom:6px; font-size:13px; }
.integrity-row:last-child { margin-bottom:0; }
.integrity-dot { width:8px; height:8px; border-radius:50%; flex-shrink:0; }
.integrity-dot.ok { background:var(--green); }
.integrity-dot.warn { background:var(--orange); }
.integrity-label { color:var(--text-secondary); }
.integrity-value { font-family:var(--font-mono); font-size:12px; color:var(--text-muted); margin-left:auto; }

/* === FOOTER === */
.footer { padding:24px; text-align:center; font-size:11px; color:var(--text-muted); }
.footer code { font-family:var(--font-mono); background:var(--bg-surface); padding:2px 6px;
  border-radius:3px; font-size:11px; border:1px solid var(--border); }

/* === PRINT === */
@media print {
  :root { --bg-primary:#fff; --bg-surface:#fff; --bg-elevated:#f6f8fa; --border:#d0d7de;
    --border-light:#d0d7de; --text-primary:#1f2328; --text-secondary:#656d76; --text-muted:#656d76; }
  .topbar,.sidebar { display:none; }
  .main { margin:0; }
  .page { display:block!important; page-break-inside:avoid; padding:16px 0; }
  .search-input,.topbar-btn,.pagination { display:none; }
}

/* === A11Y === */
:focus-visible { outline:2px solid var(--accent); outline-offset:2px; }
@media (prefers-reduced-motion:reduce) { *, *::before, *::after { transition:none!important; } }
"""

JS = """
const ROWS_PER_PAGE = 50;
const pageState = {};

function initPage(id) {
  if (!pageState[id]) pageState[id] = { page: 0, sortCol: -1, sortAsc: true, filter: '' };
}

function showSection(id) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  const page = document.getElementById('page-' + id);
  const nav = document.getElementById('nav-' + id);
  if (page) page.classList.add('active');
  if (nav) nav.classList.add('active');
}

function filterTable(input, tableId) {
  const id = tableId.replace('-table','');
  initPage(id);
  pageState[id].filter = input.value.toLowerCase();
  pageState[id].page = 0;
  applyPagination(id);
}

function sortTable(tableId, colIdx) {
  const id = tableId.replace('-table','');
  initPage(id);
  const st = pageState[id];
  if (st.sortCol === colIdx) { st.sortAsc = !st.sortAsc; }
  else { st.sortCol = colIdx; st.sortAsc = true; }
  const table = document.getElementById(tableId);
  if (!table) return;
  const tbody = table.querySelector('tbody');
  const rows = Array.from(tbody.querySelectorAll('tr'));
  rows.sort((a, b) => {
    const aText = (a.cells[colIdx]?.textContent || '').trim();
    const bText = (b.cells[colIdx]?.textContent || '').trim();
    const aNum = parseFloat(aText), bNum = parseFloat(bText);
    let cmp;
    if (!isNaN(aNum) && !isNaN(bNum)) cmp = aNum - bNum;
    else cmp = aText.localeCompare(bText);
    return st.sortAsc ? cmp : -cmp;
  });
  rows.forEach(r => tbody.appendChild(r));
  table.querySelectorAll('th').forEach((th, i) => {
    th.classList.toggle('sorted', i === colIdx);
    const arrow = th.querySelector('.sort-arrow');
    if (arrow) arrow.textContent = i === colIdx ? (st.sortAsc ? '▲' : '▼') : '▲';
  });
  st.page = 0;
  applyPagination(id);
}

function applyPagination(id) {
  initPage(id);
  const st = pageState[id];
  const table = document.getElementById(id + '-table');
  if (!table) return;
  const rows = Array.from(table.querySelectorAll('tbody tr'));
  const filtered = rows.filter(r => {
    const match = !st.filter || r.textContent.toLowerCase().includes(st.filter);
    return match;
  });
  const totalPages = Math.max(1, Math.ceil(filtered.length / ROWS_PER_PAGE));
  if (st.page >= totalPages) st.page = totalPages - 1;
  const start = st.page * ROWS_PER_PAGE;
  const end = start + ROWS_PER_PAGE;
  rows.forEach(r => r.style.display = 'none');
  filtered.forEach((r, i) => { r.style.display = (i >= start && i < end) ? '' : 'none'; });
  const info = document.getElementById(id + '-page-info');
  const prevBtn = document.getElementById(id + '-prev');
  const nextBtn = document.getElementById(id + '-next');
  if (info) info.textContent = 'Page ' + (st.page + 1) + ' of ' + totalPages + ' (' + filtered.length + ' rows)';
  if (prevBtn) prevBtn.disabled = st.page <= 0;
  if (nextBtn) nextBtn.disabled = st.page >= totalPages - 1;
}

function prevPage(id) { initPage(id); pageState[id].page--; applyPagination(id); }
function nextPage(id) { initPage(id); pageState[id].page++; applyPagination(id); }

function exportCSV(tableId) {
  const table = document.getElementById(tableId);
  if (!table) return;
  let csv = [];
  const ths = table.querySelectorAll('thead th');
  csv.push(Array.from(ths).map(h => '"'+h.textContent.replace(/[▲▼]/g,'').trim().replace(/"/g,'""')+'"').join(','));
  table.querySelectorAll('tbody tr').forEach(row => {
    const cells = row.querySelectorAll('td');
    csv.push(Array.from(cells).map(c => '"'+c.textContent.replace(/"/g,'""').trim()+'"').join(','));
  });
  const blob = new Blob([csv.join('\\n')], {type:'text/csv'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = tableId.replace('-table','') + '_export.csv';
  a.click();
}

/* Keyboard nav */
document.addEventListener('keydown', e => {
  if (e.target.tagName === 'INPUT') return;
  const items = Array.from(document.querySelectorAll('.nav-item'));
  const active = document.querySelector('.nav-item.active');
  const idx = items.indexOf(active);
  if (e.key === 'ArrowDown' && idx < items.length - 1) { items[idx+1].click(); items[idx+1].focus(); e.preventDefault(); }
  if (e.key === 'ArrowUp' && idx > 0) { items[idx-1].click(); items[idx-1].focus(); e.preventDefault(); }
});

/* Init pagination on load */
document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('.page').forEach(p => {
    const id = p.id.replace('page-','');
    applyPagination(id);
  });
});
"""


def nav_item(section_id, label, count=None):
    badge = f'<span class="nav-badge">{count:,}</span>' if count is not None and count > 0 else ''
    return (
        f'<div class="nav-item" id="nav-{section_id}" role="button" tabindex="0" '
        f'aria-label="{label}" onclick="showSection(\'{section_id}\')">'
        f'<span>{label}</span>{badge}</div>'
    )


def page_header(title, count, table_id):
    return (
        f'<div class="page-header">'
        f'<div class="page-title">{title}</div>'
        f'<div class="page-toolbar">'
        f'<input class="search-input" placeholder="Search {title.lower()}…" '
        f'onkeyup="filterTable(this,\'{table_id}\')" aria-label="Search">'
        f'<span class="toolbar-spacer"></span>'
        f'<span class="count-label">{count:,} records</span>'
        f'<button class="topbar-btn" onclick="exportCSV(\'{table_id}\')">Export CSV</button>'
        f'</div></div>'
    )


def table_start(table_id, headers):
    ths = ''.join(
        f'<th onclick="sortTable(\'{table_id}\',{i})">{h} <span class="sort-arrow">▲</span></th>'
        for i, h in enumerate(headers)
    )
    return f'<div class="table-container"><div class="table-scroll"><table id="{table_id}"><thead><tr>{ths}</tr></thead><tbody>'


def table_end(section_id):
    return (
        f'</tbody></table></div>'
        f'<div class="pagination">'
        f'<button id="{section_id}-prev" onclick="prevPage(\'{section_id}\')">← Previous</button>'
        f'<span class="page-info" id="{section_id}-page-info"></span>'
        f'<button id="{section_id}-next" onclick="nextPage(\'{section_id}\')">Next →</button>'
        f'</div></div>'
    )


def badge(text, style=None):
    if not style:
        style = str(text).lower().replace(' ', '-')
    return f'<span class="badge badge-{style}">{text}</span>'
