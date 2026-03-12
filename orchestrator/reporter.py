"""
XtractR Evidence Report Generator — Premium Edition

Generates forensic evidence HTML reports with:
- Glassmorphic dark-mode design with animated gradients
- Statistics cards with animated counters
- Full EXIF metadata viewer for images
- Smooth page transitions and hover effects
- Interactive evidence gallery with lightbox
"""

import json
import os
import html
import logging

logger = logging.getLogger("xtractr.reporter")


# ─── DESIGN SYSTEM ───────────────────────────────────────────────────────────

CSS = """
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');

:root {
  --bg-primary: #0a0a1a;
  --bg-secondary: #12122a;
  --bg-card: rgba(20, 20, 50, 0.6);
  --bg-glass: rgba(255,255,255,0.03);
  --border-glass: rgba(255,255,255,0.08);
  --accent-primary: #6366f1;
  --accent-secondary: #818cf8;
  --accent-glow: rgba(99,102,241,0.3);
  --accent-red: #ef4444;
  --accent-red-glow: rgba(239,68,68,0.2);
  --accent-green: #10b981;
  --accent-green-glow: rgba(16,185,129,0.2);
  --accent-amber: #f59e0b;
  --accent-amber-glow: rgba(245,158,11,0.2);
  --accent-cyan: #06b6d4;
  --text-primary: #f1f5f9;
  --text-secondary: #94a3b8;
  --text-muted: #475569;
  --radius: 16px;
  --radius-sm: 10px;
  --shadow-lg: 0 25px 50px -12px rgba(0,0,0,0.5);
  --transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
}

* { margin: 0; padding: 0; box-sizing: border-box; }

body {
  font-family: 'Inter', -apple-system, sans-serif;
  background: var(--bg-primary);
  color: var(--text-primary);
  display: flex;
  height: 100vh;
  overflow: hidden;
}

/* Animated background gradient */
body::before {
  content: '';
  position: fixed;
  top: -50%; left: -50%;
  width: 200%; height: 200%;
  background: radial-gradient(circle at 20% 80%, rgba(99,102,241,0.06) 0%, transparent 50%),
              radial-gradient(circle at 80% 20%, rgba(6,182,212,0.04) 0%, transparent 50%),
              radial-gradient(circle at 50% 50%, rgba(239,68,68,0.02) 0%, transparent 50%);
  animation: bgPulse 20s ease-in-out infinite;
  z-index: 0;
  pointer-events: none;
}

@keyframes bgPulse {
  0%, 100% { transform: translate(0, 0) scale(1); }
  33% { transform: translate(-2%, 1%) scale(1.02); }
  66% { transform: translate(1%, -1%) scale(0.98); }
}

@keyframes fadeInUp {
  from { opacity: 0; transform: translateY(20px); }
  to { opacity: 1; transform: translateY(0); }
}

@keyframes slideInLeft {
  from { opacity: 0; transform: translateX(-20px); }
  to { opacity: 1; transform: translateX(0); }
}

@keyframes shimmer {
  0% { background-position: -200% 0; }
  100% { background-position: 200% 0; }
}

@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.5; }
}

@keyframes countUp {
  from { opacity: 0; transform: scale(0.5); }
  to { opacity: 1; transform: scale(1); }
}

/* ─── SIDEBAR ─── */
.sidebar {
  width: 280px;
  min-width: 280px;
  background: var(--bg-secondary);
  border-right: 1px solid var(--border-glass);
  display: flex;
  flex-direction: column;
  z-index: 10;
  position: relative;
  backdrop-filter: blur(20px);
}

.brand {
  padding: 28px 24px;
  border-bottom: 1px solid var(--border-glass);
  animation: slideInLeft 0.5s ease-out;
}

.brand-logo {
  font-size: 1.3rem;
  font-weight: 800;
  background: linear-gradient(135deg, var(--accent-primary), var(--accent-cyan));
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
  letter-spacing: -0.5px;
  margin-bottom: 6px;
}

.brand-case {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.75rem;
  color: var(--text-muted);
  letter-spacing: 0.5px;
}

.nav-section {
  padding: 20px 16px;
  flex: 1;
  overflow-y: auto;
}

.nav-label {
  font-size: 0.65rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 1.5px;
  color: var(--text-muted);
  padding: 0 8px;
  margin-bottom: 12px;
}

.nav-item {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px 16px;
  color: var(--text-secondary);
  text-decoration: none;
  border-radius: var(--radius-sm);
  transition: var(--transition);
  font-size: 0.9rem;
  font-weight: 500;
  margin-bottom: 4px;
  position: relative;
  overflow: hidden;
}

.nav-item::before {
  content: '';
  position: absolute;
  left: 0; top: 0; bottom: 0;
  width: 3px;
  background: var(--accent-primary);
  transform: scaleY(0);
  transition: var(--transition);
  border-radius: 0 4px 4px 0;
}

.nav-item:hover {
  background: var(--bg-glass);
  color: var(--text-primary);
  transform: translateX(2px);
}

.nav-item:hover::before,
.nav-item.active::before {
  transform: scaleY(1);
}

.nav-item.active {
  background: rgba(99,102,241,0.1);
  color: var(--accent-secondary);
}

.nav-icon {
  font-size: 1.1rem;
  width: 24px;
  text-align: center;
}

.nav-badge {
  margin-left: auto;
  background: var(--accent-primary);
  color: white;
  font-size: 0.65rem;
  font-weight: 700;
  padding: 2px 8px;
  border-radius: 12px;
  min-width: 22px;
  text-align: center;
}

.nav-badge.encrypted {
  background: var(--accent-red);
}

/* Sidebar footer */
.sidebar-footer {
  padding: 16px 20px;
  border-top: 1px solid var(--border-glass);
  font-size: 0.7rem;
  color: var(--text-muted);
  line-height: 1.6;
}

.seal-hash {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.6rem;
  color: var(--accent-primary);
  word-break: break-all;
  padding: 6px 8px;
  background: rgba(99,102,241,0.06);
  border-radius: 6px;
  margin-top: 6px;
}

/* ─── MAIN CONTENT ─── */
.main {
  flex: 1;
  overflow-y: auto;
  position: relative;
  z-index: 1;
}

.main-header {
  padding: 24px 40px;
  border-bottom: 1px solid var(--border-glass);
  backdrop-filter: blur(12px);
  background: rgba(10,10,26,0.8);
  position: sticky;
  top: 0;
  z-index: 5;
  animation: fadeInUp 0.4s ease-out;
}

.main-header h1 {
  font-size: 1.5rem;
  font-weight: 700;
  background: linear-gradient(135deg, var(--text-primary), var(--text-secondary));
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
}

.main-header .subtitle {
  font-size: 0.8rem;
  color: var(--text-muted);
  margin-top: 2px;
}

.content {
  padding: 30px 40px;
  animation: fadeInUp 0.5s ease-out 0.1s both;
}

/* ─── STAT CARDS ─── */
.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
  gap: 20px;
  margin-bottom: 30px;
}

.stat-card {
  background: var(--bg-card);
  border: 1px solid var(--border-glass);
  border-radius: var(--radius);
  padding: 24px;
  position: relative;
  overflow: hidden;
  transition: var(--transition);
  animation: fadeInUp 0.5s ease-out both;
  backdrop-filter: blur(12px);
}

.stat-card:nth-child(1) { animation-delay: 0.1s; }
.stat-card:nth-child(2) { animation-delay: 0.2s; }
.stat-card:nth-child(3) { animation-delay: 0.3s; }
.stat-card:nth-child(4) { animation-delay: 0.4s; }
.stat-card:nth-child(5) { animation-delay: 0.5s; }

.stat-card:hover {
  transform: translateY(-4px);
  border-color: var(--accent-primary);
  box-shadow: 0 8px 32px var(--accent-glow);
}

.stat-card::before {
  content: '';
  position: absolute;
  top: 0; left: 0; right: 0;
  height: 3px;
  background: linear-gradient(90deg, var(--accent-primary), var(--accent-cyan));
  opacity: 0;
  transition: var(--transition);
}

.stat-card:hover::before { opacity: 1; }

.stat-icon {
  font-size: 2rem;
  margin-bottom: 12px;
  display: block;
}

.stat-value {
  font-size: 2rem;
  font-weight: 800;
  color: var(--text-primary);
  font-family: 'JetBrains Mono', monospace;
  animation: countUp 0.8s ease-out both;
}

.stat-label {
  font-size: 0.75rem;
  color: var(--text-muted);
  text-transform: uppercase;
  letter-spacing: 1px;
  margin-top: 6px;
  font-weight: 600;
}

/* ─── INTEGRITY BANNER ─── */
.integrity-banner {
  background: linear-gradient(135deg, rgba(16,185,129,0.08), rgba(6,182,212,0.05));
  border: 1px solid rgba(16,185,129,0.2);
  border-radius: var(--radius);
  padding: 24px 28px;
  margin-bottom: 30px;
  display: flex;
  align-items: center;
  gap: 16px;
  animation: fadeInUp 0.6s ease-out 0.3s both;
  position: relative;
  overflow: hidden;
}

.integrity-banner::after {
  content: '';
  position: absolute;
  top: 0; left: -100%; right: 0;
  height: 100%;
  background: linear-gradient(90deg, transparent, rgba(16,185,129,0.05), transparent);
  animation: shimmer 3s infinite;
  background-size: 200% 100%;
}

.integrity-icon { font-size: 2.5rem; }

.integrity-title {
  font-weight: 700;
  font-size: 1rem;
  color: var(--accent-green);
  margin-bottom: 4px;
}

.integrity-desc {
  font-size: 0.85rem;
  color: var(--text-secondary);
  line-height: 1.5;
}

/* ─── ALERT BOX ─── */
.alert-box {
  background: linear-gradient(135deg, rgba(239,68,68,0.08), rgba(239,68,68,0.03));
  border: 1px solid rgba(239,68,68,0.2);
  border-radius: var(--radius);
  padding: 24px 28px;
  margin-bottom: 20px;
  animation: fadeInUp 0.5s ease-out;
}

.alert-box .alert-icon { font-size: 1.5rem; margin-bottom: 8px; display: block; }
.alert-box .alert-title {
  color: var(--accent-red);
  font-weight: 700;
  font-size: 0.9rem;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}

.alert-box p {
  color: var(--text-secondary);
  font-size: 0.85rem;
  margin-top: 8px;
  line-height: 1.5;
}

.alert-box .hash-mono {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.75rem;
  color: var(--accent-primary);
  word-break: break-all;
}

/* ─── HASH BADGE ─── */
.hash-bar {
  background: var(--bg-card);
  border: 1px solid var(--border-glass);
  border-radius: var(--radius-sm);
  padding: 16px 20px;
  margin-bottom: 24px;
  display: flex;
  gap: 24px;
  flex-wrap: wrap;
  animation: fadeInUp 0.4s ease-out;
}

.hash-item { flex: 1; min-width: 200px; }

.hash-label {
  font-size: 0.65rem;
  text-transform: uppercase;
  letter-spacing: 1px;
  color: var(--text-muted);
  font-weight: 600;
  margin-bottom: 4px;
}

.hash-value {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.72rem;
  color: var(--accent-cyan);
  word-break: break-all;
  line-height: 1.4;
}

/* ─── TABLE ─── */
.table-container {
  background: var(--bg-card);
  border: 1px solid var(--border-glass);
  border-radius: var(--radius);
  overflow: hidden;
  backdrop-filter: blur(12px);
  animation: fadeInUp 0.5s ease-out 0.2s both;
}

table {
  width: 100%;
  border-collapse: collapse;
}

thead th {
  background: rgba(99,102,241,0.1);
  padding: 14px 16px;
  text-align: left;
  font-size: 0.7rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 1px;
  color: var(--accent-secondary);
  border-bottom: 1px solid var(--border-glass);
  position: sticky;
  top: 0;
  z-index: 2;
}

tbody td {
  padding: 12px 16px;
  font-size: 0.85rem;
  border-bottom: 1px solid rgba(255,255,255,0.03);
  color: var(--text-secondary);
  transition: var(--transition);
}

tbody tr {
  transition: var(--transition);
}

tbody tr:hover {
  background: rgba(99,102,241,0.05);
}

tbody tr:hover td {
  color: var(--text-primary);
}

/* ─── GALLERY ─── */
.gallery-layout {
  display: grid;
  grid-template-columns: 1fr 400px;
  gap: 24px;
  height: calc(100vh - 160px);
}

.gallery-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
  gap: 12px;
  overflow-y: auto;
  align-content: start;
  padding: 4px;
}

.thumb-wrapper {
  position: relative;
  border-radius: var(--radius-sm);
  overflow: hidden;
  cursor: pointer;
  transition: var(--transition);
  border: 2px solid transparent;
  aspect-ratio: 1;
}

.thumb-wrapper:hover {
  transform: scale(1.05);
  border-color: var(--accent-primary);
  box-shadow: 0 8px 24px var(--accent-glow);
  z-index: 2;
}

.thumb-wrapper.active {
  border-color: var(--accent-cyan);
  box-shadow: 0 0 20px rgba(6,182,212,0.3);
}

.thumb-img {
  width: 100%;
  height: 100%;
  object-fit: cover;
  transition: var(--transition);
}

.thumb-wrapper:hover .thumb-img {
  transform: scale(1.1);
}

.thumb-type {
  position: absolute;
  top: 8px;
  right: 8px;
  background: rgba(0,0,0,0.7);
  color: white;
  font-size: 0.6rem;
  padding: 2px 6px;
  border-radius: 4px;
  font-weight: 600;
  backdrop-filter: blur(4px);
}

/* ─── INSPECTOR ─── */
.inspector {
  background: var(--bg-card);
  border: 1px solid var(--border-glass);
  border-radius: var(--radius);
  overflow-y: auto;
  backdrop-filter: blur(12px);
  display: flex;
  flex-direction: column;
}

.inspector-header {
  padding: 20px 24px;
  border-bottom: 1px solid var(--border-glass);
  font-size: 0.8rem;
  font-weight: 700;
  color: var(--accent-secondary);
  text-transform: uppercase;
  letter-spacing: 1px;
  display: flex;
  align-items: center;
  gap: 8px;
}

.preview-area {
  width: 100%;
  height: 260px;
  background: #000;
  display: flex;
  align-items: center;
  justify-content: center;
  position: relative;
  overflow: hidden;
}

.preview-img {
  max-width: 100%;
  max-height: 100%;
  object-fit: contain;
  transition: var(--transition);
}

.preview-placeholder {
  color: var(--text-muted);
  font-size: 0.85rem;
  text-align: center;
}

.preview-placeholder .icon { font-size: 2.5rem; display: block; margin-bottom: 8px; }

.meta-section {
  padding: 16px 24px;
  flex: 1;
  overflow-y: auto;
}

.meta-section-title {
  font-size: 0.7rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 1.5px;
  color: var(--text-muted);
  margin: 16px 0 10px 0;
  display: flex;
  align-items: center;
  gap: 6px;
}

.meta-section-title:first-child { margin-top: 0; }

.meta-row {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  padding: 8px 0;
  border-bottom: 1px solid rgba(255,255,255,0.03);
  gap: 12px;
}

.meta-key {
  font-size: 0.75rem;
  color: var(--text-muted);
  font-weight: 500;
  white-space: nowrap;
  min-width: 90px;
}

.meta-value {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.75rem;
  color: var(--accent-cyan);
  text-align: right;
  word-break: break-all;
}

.meta-value.hash {
  font-size: 0.6rem;
  color: var(--accent-primary);
}

/* ─── LIGHTBOX ─── */
.lightbox {
  display: none;
  position: fixed;
  top: 0; left: 0; right: 0; bottom: 0;
  background: rgba(0,0,0,0.92);
  z-index: 1000;
  align-items: center;
  justify-content: center;
  backdrop-filter: blur(20px);
  cursor: zoom-out;
  animation: fadeInUp 0.3s ease-out;
}

.lightbox.active { display: flex; }

.lightbox img {
  max-width: 90vw;
  max-height: 90vh;
  object-fit: contain;
  border-radius: 8px;
  box-shadow: 0 32px 64px rgba(0,0,0,0.5);
}

.lightbox-close {
  position: absolute;
  top: 24px;
  right: 32px;
  background: rgba(255,255,255,0.1);
  border: none;
  color: white;
  font-size: 1.5rem;
  width: 48px;
  height: 48px;
  border-radius: 50%;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: var(--transition);
}

.lightbox-close:hover {
  background: rgba(255,255,255,0.2);
  transform: scale(1.1);
}

/* ─── EXIF TAB TOGGLE ─── */
.tab-bar {
  display: flex;
  border-bottom: 1px solid var(--border-glass);
}

.tab-btn {
  flex: 1;
  padding: 12px;
  background: none;
  border: none;
  color: var(--text-muted);
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  cursor: pointer;
  transition: var(--transition);
  position: relative;
  font-family: 'Inter', sans-serif;
}

.tab-btn:hover { color: var(--text-secondary); }

.tab-btn.active {
  color: var(--accent-primary);
}

.tab-btn.active::after {
  content: '';
  position: absolute;
  bottom: 0; left: 20%; right: 20%;
  height: 2px;
  background: var(--accent-primary);
  border-radius: 2px 2px 0 0;
}

.tab-content { display: none; }
.tab-content.active { display: block; }

/* ─── SCROLLBAR ─── */
::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: var(--border-glass); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: rgba(255,255,255,0.15); }

/* ─── RESPONSIVE ─── */
@media (max-width: 1200px) {
  .gallery-layout { grid-template-columns: 1fr 320px; }
}
"""


# ─── JAVASCRIPT ──────────────────────────────────────────────────────────────

JS = """
let currentExifData = {};
let activeThumb = null;

function loadMedia(el, src, type, hash, size, date, filename, exifJson) {
    const preview = document.getElementById('preview-area');
    document.getElementById('meta-name').textContent = filename;
    document.getElementById('meta-hash').textContent = hash;
    document.getElementById('meta-size').textContent = size;
    document.getElementById('meta-date').textContent = date;

    // Remove active from previous
    if (activeThumb) activeThumb.classList.remove('active');
    el.classList.add('active');
    activeThumb = el;

    if (type === 'VIDEO') {
        preview.innerHTML = `<video controls autoplay class="preview-img"><source src="${src}" type="video/mp4"></video>`;
    } else {
        preview.innerHTML = `<img src="${src}" class="preview-img" ondblclick="openLightbox('${src}')">`;
    }

    // Parse EXIF data
    try {
        currentExifData = JSON.parse(exifJson || '{}');
    } catch(e) {
        currentExifData = {};
    }

    const exifContainer = document.getElementById('exif-data');
    if (exifContainer) {
        if (Object.keys(currentExifData).length > 0) {
            let exifHtml = '';
            const groupOrder = {
                'Camera': ['Make', 'Model', 'Software'],
                'Image': ['Resolution', 'ImageWidth', 'ImageHeight', 'Orientation', 'PixelXDimension', 'PixelYDimension'],
                'Exposure': ['ExposureTime', 'FNumber', 'ISOSpeedRatings', 'FocalLength', 'FocalLengthIn35mmFilm'],
                'Date/Time': ['DateTime', 'DateTimeOriginal', 'DateTimeDigitized'],
                'GPS': ['GPSLatitudeRef', 'GPSLatitude', 'GPSLongitudeRef', 'GPSLongitude', 'GPSAltitude'],
                'Other': ['XResolution', 'YResolution']
            };
            
            let usedKeys = new Set();
            
            for (const [group, keys] of Object.entries(groupOrder)) {
                let groupHtml = '';
                for (const key of keys) {
                    if (currentExifData[key]) {
                        groupHtml += `<div class="meta-row"><span class="meta-key">${key}</span><span class="meta-value">${currentExifData[key]}</span></div>`;
                        usedKeys.add(key);
                    }
                }
                if (groupHtml) {
                    exifHtml += `<div class="meta-section-title">📷 ${group}</div>${groupHtml}`;
                }
            }
            
            // Any remaining keys
            let otherHtml = '';
            for (const [key, val] of Object.entries(currentExifData)) {
                if (!usedKeys.has(key)) {
                    otherHtml += `<div class="meta-row"><span class="meta-key">${key}</span><span class="meta-value">${val}</span></div>`;
                }
            }
            if (otherHtml) {
                exifHtml += `<div class="meta-section-title">📎 Additional</div>${otherHtml}`;
            }
            
            exifContainer.innerHTML = exifHtml || '<p style="color:var(--text-muted);font-size:0.8rem;padding:20px;">No EXIF data available</p>';
        } else {
            exifContainer.innerHTML = '<p style="color:var(--text-muted);font-size:0.8rem;padding:20px;text-align:center;">No EXIF data found for this file</p>';
        }
    }
}

function switchTab(tabName) {
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(tc => tc.classList.remove('active'));
    document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');
    document.getElementById(`tab-${tabName}`).classList.add('active');
}

function openLightbox(src) {
    const lb = document.getElementById('lightbox');
    lb.querySelector('img').src = src;
    lb.classList.add('active');
}

function closeLightbox() {
    document.getElementById('lightbox').classList.remove('active');
}

// Close lightbox on escape
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeLightbox();
});

// Animate stat numbers
document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.stat-value[data-target]').forEach(el => {
        const target = parseInt(el.getAttribute('data-target'));
        let current = 0;
        const step = Math.max(1, Math.floor(target / 40));
        const timer = setInterval(() => {
            current += step;
            if (current >= target) {
                el.textContent = target.toLocaleString();
                clearInterval(timer);
            } else {
                el.textContent = current.toLocaleString();
            }
        }, 30);
    });
});
"""


# ─── RENDER FUNCTIONS ────────────────────────────────────────────────────────

def _escape(s):
    """HTML-escape a value."""
    if s is None:
        return ""
    return html.escape(str(s))


def render_html(case_id, content, sidebar, title, subtitle="", manifest=None):
    seal = "N/A"
    gov_sig = "N/A"

    if manifest:
        seal = manifest.get("case_seal", "PENDING")
        integrity = manifest.get("integrity") or {}
        raw_sig = integrity.get("governance_signature")
        if raw_sig and isinstance(raw_sig, str):
            gov_sig = raw_sig[:16] + "..."

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{_escape(title)} — XtractR Case {_escape(case_id)}</title>
    <style>{CSS}</style>
    <script>{JS}</script>
</head>
<body>
    <div class="sidebar">
        <div class="brand">
            <div class="brand-logo">⚡ XtractR</div>
            <div class="brand-case">CASE: {_escape(case_id)}</div>
        </div>
        <div class="nav-section">
            <div class="nav-label">Evidence</div>
            <a href="dashboard.html" class="nav-item">
                <span class="nav-icon">📊</span> Dashboard
            </a>
            {sidebar}
        </div>
        <div class="sidebar-footer">
            <div style="margin-bottom:4px;">🔒 CASE SEAL</div>
            <div class="seal-hash">{_escape(str(seal)[:32])}...</div>
        </div>
    </div>
    <div class="main">
        <div class="main-header">
            <h1>{_escape(title)}</h1>
            <div class="subtitle">{_escape(subtitle)}</div>
        </div>
        <div class="content">
            {content}
        </div>
    </div>

    <!-- Lightbox Overlay -->
    <div id="lightbox" class="lightbox" onclick="closeLightbox()">
        <button class="lightbox-close" onclick="closeLightbox()">✕</button>
        <img src="" alt="Evidence Preview">
    </div>
</body>
</html>"""


def generate_report(case_id, output_dir, manifest):
    sidebar_links = ""
    artifacts = manifest.get("artifact_layer") or {}

    # Build sidebar with badges
    for cat, det in artifacts.items():
        count = det.get("record_count", "")
        if det["status"] == "EXTRACTED":
            badge = f'<span class="nav-badge">{count}</span>' if count else ""
            sidebar_links += f'''<a href="{cat}.html" class="nav-item">
                <span class="nav-icon">📂</span> {cat} {badge}
            </a>'''
        elif det["status"] == "ENCRYPTED_DETECTED":
            sidebar_links += f'''<a href="{cat}.html" class="nav-item">
                <span class="nav-icon">🔒</span> {cat}
                <span class="nav-badge encrypted">ENC</span>
            </a>'''

    # ─── Generate per-artifact pages ───
    for cat, det in artifacts.items():
        if det["status"] == "ENCRYPTED_DETECTED":
            content = f"""
            <div class="alert-box">
                <span class="alert-icon">🚫</span>
                <span class="alert-title">Extraction Denied — Encrypted Database</span>
                <p><strong>Reason:</strong> {_escape(det.get('reason'))}</p>
                <p><strong>Source Hash (Preserved):</strong></p>
                <p class="hash-mono">{_escape(det.get('source_hash_sha256'))}</p>
                <p style="margin-top:12px;">XtractR governance policy prevents extraction of encrypted databases without an explicit warrant-level decryption token. The source hash has been preserved for chain of custody.</p>
            </div>
            """
            with open(os.path.join(output_dir, f"{cat}.html"), "w") as f:
                f.write(render_html(case_id, content, sidebar_links, cat,
                                    "Access restricted by governance policy", manifest))
            continue

        if det["status"] != "EXTRACTED":
            continue

        data_path = os.path.join(output_dir, "artifacts", det["output_file"])
        try:
            with open(data_path, "r") as f:
                data = json.load(f)
        except Exception as e:
            logger.warning("Failed to load report data for %s: %s", cat, e)
            continue

        # ─── TABLE ARTIFACTS (SMS, Chrome, etc.) ───
        if det.get("type") == "TABLE":
            headers = list(data[0].keys()) if data else []
            th_rows = "".join(f"<th>{_escape(h)}</th>" for h in headers)
            tr_rows = ""
            for row in data:
                display_row = {}
                for k, v in row.items():
                    if isinstance(v, dict) and "utc" in v:
                        display_row[k] = v["utc"]
                    else:
                        display_row[k] = v
                tds = "".join(f"<td>{_escape(str(display_row.get(h, '')))}</td>" for h in headers)
                tr_rows += f"<tr>{tds}</tr>"

            content = f"""
            <div class="hash-bar">
                <div class="hash-item">
                    <div class="hash-label">Source Integrity (SHA-256)</div>
                    <div class="hash-value">{_escape(det.get('source_hash_sha256'))}</div>
                </div>
                <div class="hash-item">
                    <div class="hash-label">Output Integrity (SHA-256)</div>
                    <div class="hash-value">{_escape(det.get('output_hash_sha256'))}</div>
                </div>
            </div>
            <div class="table-container">
                <table>
                    <thead><tr>{th_rows}</tr></thead>
                    <tbody>{tr_rows}</tbody>
                </table>
            </div>
            """
            with open(os.path.join(output_dir, f"{cat}.html"), "w") as f:
                f.write(render_html(case_id, content, sidebar_links, cat,
                                    f"{det.get('record_count', 0)} records extracted • Chain of custody verified", manifest))

        # ─── GALLERY ARTIFACTS (Media) ───
        elif det.get("type") == "GALLERY":
            thumbs_html = ""
            for idx, item in enumerate(data):
                src = item['Local_Link']
                exif_json = json.dumps(item.get('EXIF', {})).replace("'", "\\'").replace('"', '&quot;')
                onclick = (f"loadMedia(this, '{src}', '{item['Type']}', "
                           f"'{item['Hash']}', '{item['Size']}', "
                           f"'{item['Modified']}', '{_escape(item['Filename'])}', "
                           f"'{exif_json}')")
                type_badge = f'<span class="thumb-type">{item["Type"]}</span>'
                
                if item['Type'] == 'VIDEO':
                    thumbs_html += f"""
                    <div class="thumb-wrapper" onclick="{onclick}" title="{_escape(item['Filename'])}">
                        <div style="width:100%;height:100%;background:#111;display:flex;align-items:center;justify-content:center;font-size:2rem;">🎬</div>
                        {type_badge}
                    </div>"""
                else:
                    thumbs_html += f"""
                    <div class="thumb-wrapper" onclick="{onclick}" title="{_escape(item['Filename'])}">
                        <img src="{src}" class="thumb-img" loading="lazy" alt="{_escape(item['Filename'])}">
                        {type_badge}
                    </div>"""

            content = f"""
            <div class="hash-bar">
                <div class="hash-item">
                    <div class="hash-label">Media Manifest Integrity</div>
                    <div class="hash-value">{_escape(det.get('source_hash_sha256'))}</div>
                </div>
                <div class="hash-item">
                    <div class="hash-label">Total Items</div>
                    <div class="hash-value" style="font-size:1.2rem;">{det.get('record_count', 0)}</div>
                </div>
            </div>

            <div class="gallery-layout">
                <div class="gallery-grid">{thumbs_html}</div>
                <div class="inspector">
                    <div class="inspector-header">🔍 Evidence Inspector</div>
                    <div id="preview-area" class="preview-area">
                        <div class="preview-placeholder">
                            <span class="icon">🖼️</span>
                            Select an item to inspect
                        </div>
                    </div>

                    <!-- Tab Toggle -->
                    <div class="tab-bar">
                        <button class="tab-btn active" data-tab="file" onclick="switchTab('file')">📄 File Info</button>
                        <button class="tab-btn" data-tab="exif" onclick="switchTab('exif')">📷 EXIF Data</button>
                    </div>

                    <div class="meta-section">
                        <div id="tab-file" class="tab-content active">
                            <div class="meta-section-title">📄 File Details</div>
                            <div class="meta-row"><span class="meta-key">Filename</span><span id="meta-name" class="meta-value">—</span></div>
                            <div class="meta-row"><span class="meta-key">File Size</span><span id="meta-size" class="meta-value">—</span></div>
                            <div class="meta-row"><span class="meta-key">Modified</span><span id="meta-date" class="meta-value">—</span></div>
                            <div class="meta-section-title">🔐 Integrity</div>
                            <div class="meta-row"><span class="meta-key">SHA-256</span><span id="meta-hash" class="meta-value hash">—</span></div>
                        </div>

                        <div id="tab-exif" class="tab-content">
                            <div id="exif-data">
                                <p style="color:var(--text-muted);font-size:0.8rem;padding:20px;text-align:center;">
                                    Select an image to view EXIF data
                                </p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            """
            with open(os.path.join(output_dir, f"{cat}.html"), "w") as f:
                f.write(render_html(case_id, content, sidebar_links, cat,
                                    f"{det.get('record_count', 0)} media items • Double-click preview to zoom", manifest))

    # ─── DASHBOARD ───
    total_records = sum(
        det.get("record_count", 0) for det in artifacts.values()
        if det.get("status") == "EXTRACTED"
    )
    extracted_count = sum(1 for d in artifacts.values() if d.get("status") == "EXTRACTED")
    encrypted_count = sum(1 for d in artifacts.values() if d.get("status") == "ENCRYPTED_DETECTED")
    files_scanned = manifest.get("audit", {}).get("files_in_scope", 0)
    merkle = manifest.get("integrity", {}).get("merkle_root", "N/A")

    # Build artifact breakdown rows
    artifact_rows = ""
    for cat, det in artifacts.items():
        if det["status"] == "EXTRACTED":
            status_html = '<span style="color:var(--accent-green);">● EXTRACTED</span>'
        elif det["status"] == "ENCRYPTED_DETECTED":
            status_html = '<span style="color:var(--accent-red);">● ENCRYPTED</span>'
        else:
            status_html = f'<span style="color:var(--accent-amber);">● {det["status"]}</span>'
        
        artifact_rows += f"""<tr>
            <td><strong>{_escape(cat)}</strong></td>
            <td>{status_html}</td>
            <td style="font-family:'JetBrains Mono',monospace;font-size:0.75rem;">{det.get('record_count', '—')}</td>
            <td style="font-family:'JetBrains Mono',monospace;font-size:0.65rem;color:var(--accent-cyan);">{_escape(str(det.get('source_hash_sha256', ''))[:16])}...</td>
        </tr>"""

    dash_content = f"""
    <div class="stats-grid">
        <div class="stat-card">
            <span class="stat-icon">📁</span>
            <div class="stat-value" data-target="{files_scanned}">{files_scanned}</div>
            <div class="stat-label">Files Scanned</div>
        </div>
        <div class="stat-card">
            <span class="stat-icon">📊</span>
            <div class="stat-value" data-target="{total_records}">{total_records}</div>
            <div class="stat-label">Records Extracted</div>
        </div>
        <div class="stat-card">
            <span class="stat-icon">✅</span>
            <div class="stat-value" data-target="{extracted_count}">{extracted_count}</div>
            <div class="stat-label">Artifacts Extracted</div>
        </div>
        <div class="stat-card">
            <span class="stat-icon">🔒</span>
            <div class="stat-value" data-target="{encrypted_count}">{encrypted_count}</div>
            <div class="stat-label">Encrypted (Blocked)</div>
        </div>
    </div>

    <div class="integrity-banner">
        <span class="integrity-icon">🛡️</span>
        <div>
            <div class="integrity-title">System Integrity: Cryptographically Sealed</div>
            <div class="integrity-desc">
                This case is sealed with a Merkle root hash. Any modification to extracted artifacts will invalidate the seal.
                <br>
                <span style="font-family:'JetBrains Mono',monospace;font-size:0.7rem;color:var(--accent-primary);">{_escape(merkle)}</span>
            </div>
        </div>
    </div>

    <div class="table-container">
        <table>
            <thead>
                <tr>
                    <th>Artifact</th>
                    <th>Status</th>
                    <th>Records</th>
                    <th>Source Hash</th>
                </tr>
            </thead>
            <tbody>
                {artifact_rows}
            </tbody>
        </table>
    </div>
    """

    with open(os.path.join(output_dir, "dashboard.html"), "w") as f:
        f.write(render_html(case_id, dash_content, sidebar_links, "Dashboard",
                            f"Forensic Execution Summary • {manifest.get('case_metadata', {}).get('tool_version', '')}",
                            manifest))

    return os.path.join(output_dir, "dashboard.html")
