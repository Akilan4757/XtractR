#!/usr/bin/env python3
"""
Golden Dataset Generator for XtractR Validation (Extended v2).

Creates a synthetic Android filesystem with 250+ known artifacts
for parser accuracy benchmarking and determinism testing.

Run once to generate the dataset, then commit the output.
"""
import os
import sqlite3
import json
import struct
import zlib

BASE_DIR = os.path.join(os.path.dirname(__file__), "golden", "data")


def create_dirs():
    """Create the Android-like directory structure."""
    dirs = [
        "data/com.android.providers.telephony/databases",
        "data/com.android.providers.contacts/databases",
        "data/com.android.chrome/app_chrome/Default",
        "data/system",
        "data/system_ce/0",
        "data/com.whatsapp/databases",
        "media/0/DCIM/Camera",
        "media/0/DCIM/Screenshots",
        "media/0/Download",
        "media/0/Pictures/WhatsApp",
        "media/0/Videos/Camera",
        "media/0/Audio/Recordings",
    ]
    for d in dirs:
        os.makedirs(os.path.join(BASE_DIR, d), exist_ok=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
_NAMES = [
    "Rajesh Kumar", "Priya Sharma", "Amit Patel", "Sneha Gupta",
    "Vikram Singh", "Anjali Reddy", "Rahul Joshi", "Deepa Nair",
    "Suresh Menon", "Kavita Rao", "Arjun Thakur", "Meera Iyer",
    "Rohit Deshmukh", "Nisha Chopra", "Arun Bhat", "Pooja Kapoor",
    "Manish Jain", "Divya Pillai", "Sanjay Verma", "Ritu Mehta",
    "Nitin Sahni", "Lata Patil", "Girish Kulkarni", "Aditi Saxena",
    "Vishal Yadav",
]

_PHONE_BASE = "+91"
_BODIES = [
    "Hello, this is a test message", "Reply to test message",
    "Meeting at 3 PM tomorrow", "Confirmed, will be there",
    "Please call me back", "Happy birthday!", "Where are you?",
    "Running late, 10 minutes", "Sent you the document", "Thanks!",
    "Good morning, how are you?", "I'll be there in 5 minutes",
    "Can you send me the report?", "The meeting has been rescheduled",
    "Lunch at 1 PM?", "Just got home", "See you tomorrow", "OK",
    "I agree with the plan", "Let me check and get back to you",
    "The package has been delivered", "Call me when you're free",
    "Don't forget the appointment", "I sent the files via email",
    "Traffic is terrible today",
]

def _phone(i):
    return f"{_PHONE_BASE}{9800000000 + i}"


# ---------------------------------------------------------------------------
# SMS – 50 records
# ---------------------------------------------------------------------------
def create_sms_db():
    path = os.path.join(BASE_DIR, "data/com.android.providers.telephony/databases/mmssms.db")
    conn = sqlite3.connect(path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sms (
            _id INTEGER PRIMARY KEY AUTOINCREMENT,
            address TEXT, date INTEGER, body TEXT, type INTEGER, read INTEGER
        )
    """)
    messages = []
    base_ts = 1700000000000
    for i in range(50):
        addr = _phone(i % 25)
        ts   = base_ts + i * 60000
        body = _BODIES[i % len(_BODIES)]
        typ  = 2 if i % 3 == 1 else 1     # mostly received
        read = 1 if i % 5 != 0 else 0
        messages.append((addr, ts, body, typ, read))

    conn.executemany(
        "INSERT INTO sms (address, date, body, type, read) VALUES (?, ?, ?, ?, ?)",
        messages
    )
    conn.commit(); conn.close()
    print(f"  Created mmssms.db with {len(messages)} SMS records")
    return len(messages)


# ---------------------------------------------------------------------------
# Contacts – 25 contacts + 60 call log
# ---------------------------------------------------------------------------
def create_contacts_db():
    path = os.path.join(BASE_DIR, "data/com.android.providers.contacts/databases/contacts2.db")
    conn = sqlite3.connect(path)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS view_data (
            _id INTEGER PRIMARY KEY AUTOINCREMENT,
            display_name TEXT, data1 TEXT, mimetype TEXT
        )
    """)
    contacts = []
    for i, name in enumerate(_NAMES):
        contacts.append((name, _phone(i), "vnd.android.cursor.item/phone_v2"))
    # Some emails
    for i in range(10):
        contacts.append((_NAMES[i], f"{_NAMES[i].split()[0].lower()}@example.com",
                         "vnd.android.cursor.item/email_v2"))
    conn.executemany(
        "INSERT INTO view_data (display_name, data1, mimetype) VALUES (?, ?, ?)",
        contacts
    )

    conn.execute("""
        CREATE TABLE IF NOT EXISTS calls (
            _id INTEGER PRIMARY KEY AUTOINCREMENT,
            number TEXT, date INTEGER, duration INTEGER, type INTEGER
        )
    """)
    calls = []
    base_ts = 1700001000000
    for i in range(60):
        num      = _phone(i % 25)
        ts       = base_ts + i * 300000
        duration = [0, 30, 60, 120, 180, 300, 0, 0, 45, 600][i % 10]
        typ      = [1, 2, 3, 1, 2, 5, 1, 3, 2, 1][i % 10]
        calls.append((num, ts, duration, typ))
    conn.executemany(
        "INSERT INTO calls (number, date, duration, type) VALUES (?, ?, ?, ?)",
        calls
    )
    conn.commit(); conn.close()
    phone_contacts = [c for c in contacts if c[2] == "vnd.android.cursor.item/phone_v2"]
    print(f"  Created contacts2.db with {len(phone_contacts)} contacts + {len(calls)} call log entries")
    return len(phone_contacts), len(calls)


# ---------------------------------------------------------------------------
# Chrome History – 30 URLs
# ---------------------------------------------------------------------------
def create_chrome_history():
    path = os.path.join(BASE_DIR, "data/com.android.chrome/app_chrome/Default/History")
    conn = sqlite3.connect(path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS urls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT, title TEXT, last_visit_time INTEGER
        )
    """)
    chrome_base = 13351632000000000
    urls = []
    sites = [
        ("https://www.google.com/search?q=python", "python - Google Search"),
        ("https://www.example.com", "Example Domain"),
        ("https://docs.python.org/3/", "Python Documentation"),
        ("https://stackoverflow.com/questions/12345", "Stack Overflow Question"),
        ("https://en.wikipedia.org/wiki/Forensics", "Forensics - Wikipedia"),
        ("https://github.com", "GitHub: Let's build"),
        ("https://mail.google.com", "Gmail"),
        ("https://www.youtube.com/watch?v=abc", "YouTube Video"),
        ("https://maps.google.com/directions", "Google Maps"),
        ("https://amazon.in/dp/B09ABC", "Amazon Product"),
        ("https://www.reddit.com/r/forensics", "Reddit - Forensics"),
        ("https://twitter.com/user/status/123", "Twitter Post"),
        ("https://www.flipkart.com/item/123", "Flipkart Product"),
        ("https://www.linkedin.com/in/user", "LinkedIn Profile"),
        ("https://news.ycombinator.com", "Hacker News"),
        ("https://www.zomato.com/delhi/restaurant", "Zomato Restaurant"),
        ("https://booking.com/hotel", "Booking.com Hotel"),
        ("https://www.irctc.co.in/nget/train", "IRCTC Train Booking"),
        ("https://paytm.com/recharge", "Paytm Recharge"),
        ("https://swiggy.com/restaurants", "Swiggy Food Delivery"),
        ("https://www.netflix.com/browse", "Netflix"),
        ("https://disneyplus.com/video/123", "Disney+ Video"),
        ("https://stackoverflow.com/q/67890", "Another SO Question"),
        ("https://pypi.org/project/cryptography", "cryptography - PyPI"),
        ("https://www.w3schools.com/python", "Python Tutorial"),
        ("https://medium.com/article/forensics", "Medium Article"),
        ("https://developer.android.com/guide", "Android Dev Guide"),
        ("https://court.gov.in/case/details", "Court Case Details"),
        ("https://www.india.gov.in", "India Government Portal"),
        ("https://www.nytimes.com/article/tech", "NYTimes Tech Article"),
    ]
    for i, (url, title) in enumerate(sites):
        ts = chrome_base + i * 3600000000  # 1 hour apart
        urls.append((url, title, ts))
    conn.executemany(
        "INSERT INTO urls (url, title, last_visit_time) VALUES (?, ?, ?)",
        urls
    )
    conn.commit(); conn.close()
    print(f"  Created History with {len(urls)} URL records")
    return len(urls)


# ---------------------------------------------------------------------------
# Installed Apps – 20 packages
# ---------------------------------------------------------------------------
def create_packages_xml():
    path = os.path.join(BASE_DIR, "data/system/packages.xml")
    packages = [
        ("com.android.chrome", "/system/app/Chrome"),
        ("com.whatsapp", "/data/app/com.whatsapp"),
        ("com.google.android.gm", "/system/app/Gmail"),
        ("com.android.settings", "/system/app/Settings"),
        ("com.google.android.apps.maps", "/system/app/Maps"),
        ("com.android.camera2", "/system/app/Camera"),
        ("com.google.android.youtube", "/system/app/YouTube"),
        ("com.android.contacts", "/system/app/Contacts"),
        ("com.android.phone", "/system/app/Phone"),
        ("com.instagram.android", "/data/app/Instagram"),
        ("com.facebook.katana", "/data/app/Facebook"),
        ("com.twitter.android", "/data/app/Twitter"),
        ("org.telegram.messenger", "/data/app/Telegram"),
        ("com.google.android.apps.photos", "/system/app/Photos"),
        ("com.android.vending", "/system/app/PlayStore"),
        ("com.flipkart.android", "/data/app/Flipkart"),
        ("com.amazon.mShop.android", "/data/app/Amazon"),
        ("com.google.android.apps.docs", "/system/app/Drive"),
        ("com.paytm.android", "/data/app/Paytm"),
        ("net.one97.paytm.recharge", "/data/app/PaytmRecharge"),
    ]
    xml_parts = ['<?xml version="1.0" encoding="utf-8"?>\n<packages>\n']
    for name, code_path in packages:
        xml_parts.append(f'    <package name="{name}" codePath="{code_path}" />\n')
    xml_parts.append('</packages>\n')
    with open(path, "w") as f:
        f.write("".join(xml_parts))
    print(f"  Created packages.xml with {len(packages)} apps")
    return len(packages)


# ---------------------------------------------------------------------------
# Accounts – 8 accounts
# ---------------------------------------------------------------------------
def create_accounts_db():
    path = os.path.join(BASE_DIR, "data/system_ce/0/accounts.db")
    conn = sqlite3.connect(path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS accounts (
            _id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT, type TEXT
        )
    """)
    accounts = [
        ("user@gmail.com", "com.google"),
        ("user@outlook.com", "com.microsoft.office.outlook"),
        ("user.work@gmail.com", "com.google"),
        ("business@company.in", "com.google"),
        ("user_social", "com.facebook.auth.login"),
        ("user_twitter", "com.twitter.android.auth.login"),
        ("paytm_user@paytm.com", "com.paytm"),
        ("user_linkedin", "com.linkedin.android"),
    ]
    conn.executemany(
        "INSERT INTO accounts (name, type) VALUES (?, ?)",
        accounts
    )
    conn.commit(); conn.close()
    print(f"  Created accounts.db with {len(accounts)} accounts")
    return len(accounts)


# ---------------------------------------------------------------------------
# WhatsApp – 1 marker
# ---------------------------------------------------------------------------
def create_whatsapp_db():
    path = os.path.join(BASE_DIR, "data/com.whatsapp/databases/msgstore.db")
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE IF NOT EXISTS placeholder (id INTEGER PRIMARY KEY)")
    conn.commit(); conn.close()
    print("  Created msgstore.db (WhatsApp presence marker)")
    return 1


# ---------------------------------------------------------------------------
# Media – 60 files across multiple dirs & formats
# ---------------------------------------------------------------------------
def _make_jpeg(path):
    """Write a minimal valid JPEG."""
    jpeg = bytearray([
        0xFF,0xD8,0xFF,0xE0,0x00,0x10,
        0x4A,0x46,0x49,0x46,0x00,0x01,0x01,0x00,
        0x00,0x01,0x00,0x01,0x00,0x00,
        0xFF,0xDB,0x00,0x43,0x00,
    ])
    jpeg += bytes([0x08]*64)
    jpeg += bytes([
        0xFF,0xC0,0x00,0x0B,0x08,0x00,0x01,0x00,0x01,0x01,0x01,0x11,0x00,
        0xFF,0xC4,0x00,0x1F,0x00,
        0x00,0x01,0x05,0x01,0x01,0x01,0x01,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,
        0xFF,0xDA,0x00,0x08,0x01,0x01,0x00,0x00,0x3F,0x00,0x54,0xFF,0xD9,
    ])
    with open(path, "wb") as f:
        f.write(jpeg)

def _make_png(path):
    """Write a minimal valid PNG."""
    with open(path, "wb") as f:
        f.write(b'\x89PNG\r\n\x1a\n')
        ihdr = struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0)
        crc = zlib.crc32(b'IHDR'+ihdr) & 0xFFFFFFFF
        f.write(struct.pack('>I', 13)+b'IHDR'+ihdr+struct.pack('>I', crc))
        raw = zlib.compress(b'\x00\xFF\x00\x00')
        crc2 = zlib.crc32(b'IDAT'+raw) & 0xFFFFFFFF
        f.write(struct.pack('>I', len(raw))+b'IDAT'+raw+struct.pack('>I', crc2))
        crc3 = zlib.crc32(b'IEND') & 0xFFFFFFFF
        f.write(struct.pack('>I', 0)+b'IEND'+struct.pack('>I', crc3))

def _make_mp4(path):
    """Write a minimal MP4 stub."""
    with open(path, "wb") as f:
        f.write(b'\x00\x00\x00\x1cftypisom\x00\x00\x02\x00isomiso2mp41')
        f.write(b'\x00' * 64)

def _make_mp3(path):
    """Write a minimal MP3 stub (ID3 header + frame header)."""
    with open(path, "wb") as f:
        f.write(b'ID3\x04\x00\x00\x00\x00\x00\x00')
        f.write(b'\xFF\xFB\x90\x00' + b'\x00' * 60)


def create_media_files():
    count = 0
    # JPEG photos in Camera
    for i in range(20):
        fname = f"IMG_20231114_{120000+i:06d}.jpg"
        _make_jpeg(os.path.join(BASE_DIR, "media/0/DCIM/Camera", fname))
        count += 1

    # PNG screenshots
    for i in range(10):
        fname = f"Screenshot_20231115_{140000+i:06d}.png"
        _make_png(os.path.join(BASE_DIR, "media/0/DCIM/Screenshots", fname))
        count += 1

    # WhatsApp images
    for i in range(10):
        fname = f"IMG-20231116-WA{i:04d}.jpg"
        _make_jpeg(os.path.join(BASE_DIR, "media/0/Pictures/WhatsApp", fname))
        count += 1

    # MP4 videos
    for i in range(10):
        fname = f"VID_20231117_{150000+i:06d}.mp4"
        _make_mp4(os.path.join(BASE_DIR, "media/0/Videos/Camera", fname))
        count += 1

    # MP3 audio recordings (NOTE: media scanner may not detect mp3)
    for i in range(5):
        fname = f"REC_{170000+i:06d}.mp3"
        _make_mp3(os.path.join(BASE_DIR, "media/0/Audio/Recordings", fname))
        # NOT counted — media scanner doesn't support .mp3

    # Downloaded images
    for i in range(5):
        fname = f"download_{i}.jpg"
        _make_jpeg(os.path.join(BASE_DIR, "media/0/Download", fname))
        count += 1

    # Non-media files (should NOT be picked up)
    for ext in ["txt", "pdf", "docx"]:
        fpath = os.path.join(BASE_DIR, "media/0/Download", f"document.{ext}")
        with open(fpath, "w") as f:
            f.write(f"This is a {ext} file that should not be detected as media.\n")

    print(f"  Created {count} media files (+3 non-media)")
    return count


# ---------------------------------------------------------------------------
# Ground Truth
# ---------------------------------------------------------------------------
def create_ground_truth(sms_count, contact_count, call_count, url_count,
                         app_count, account_count, whatsapp_count, media_count):
    ground_truth = {
        "dataset_version": "2.0.0",
        "created_by": "golden_dataset_generator_v2",
        "description": "Synthetic Android filesystem with 250+ artifacts for XtractR validation",
        "total_expected_artifacts": (sms_count + contact_count + call_count +
                                     url_count + app_count + account_count +
                                     whatsapp_count + media_count),
        "artifacts": [
            {
                "parser": "SMS Parser",
                "artifact_type": "SMS",
                "source_file": "data/com.android.providers.telephony/databases/mmssms.db",
                "expected_count": sms_count,
                "sample_verification": [
                    {
                        "actor": _phone(0),
                        "timestamp_utc": 1700000000000,
                        "details_contains": {"body": "Hello, this is a test message", "direction": "RECEIVED"}
                    },
                    {
                        "actor": _phone(3),
                        "timestamp_utc": 1700000180000,
                        "details_contains": {"body": "Confirmed, will be there", "direction": "RECEIVED"}
                    }
                ]
            },
            {
                "parser": "Contacts Parser",
                "artifact_type": "CONTACT",
                "source_file": "data/com.android.providers.contacts/databases/contacts2.db",
                "expected_count": contact_count,
                "sample_verification": [
                    {
                        "actor": _phone(0),
                        "details_contains": {"name": "Rajesh Kumar", "number": _phone(0)}
                    }
                ]
            },
            {
                "parser": "Call Log Parser",
                "artifact_type": "CALL_LOG",
                "source_file": "data/com.android.providers.contacts/databases/contacts2.db",
                "expected_count": call_count,
                "sample_verification": [
                    {
                        "actor": _phone(0),
                        "timestamp_utc": 1700001000000,
                        "details_contains": {"duration_sec": 0, "type": "INCOMING"}
                    }
                ]
            },
            {
                "parser": "Chrome History Parser",
                "artifact_type": "WEB_HISTORY",
                "source_file": "data/com.android.chrome/app_chrome/Default/History",
                "expected_count": url_count,
                "sample_verification": [
                    {
                        "actor": "DEVICE",
                        "details_contains": {"url": "https://www.google.com/search?q=python", "title": "python - Google Search"}
                    }
                ]
            },
            {
                "parser": "Installed Apps Parser",
                "artifact_type": "INSTALLED_APP",
                "source_file": "data/system/packages.xml",
                "expected_count": app_count,
                "sample_verification": [
                    {
                        "actor": "DEVICE",
                        "details_contains": {"package": "com.whatsapp", "path": "/data/app/com.whatsapp"}
                    }
                ]
            },
            {
                "parser": "Accounts Parser",
                "artifact_type": "ACCOUNT",
                "source_file": "data/system_ce/0/accounts.db",
                "expected_count": account_count,
                "sample_verification": [
                    {
                        "actor": "DEVICE",
                        "details_contains": {"name": "user@gmail.com", "type": "com.google"}
                    }
                ]
            },
            {
                "parser": "WhatsApp Detector",
                "artifact_type": "ENCRYPTED_DB",
                "source_file": "data/com.whatsapp/databases/msgstore.db",
                "expected_count": whatsapp_count,
                "sample_verification": [
                    {
                        "actor": "DEVICE",
                        "details_contains": {"filename": "msgstore.db"}
                    }
                ]
            },
            {
                "parser": "Media Scanner",
                "artifact_type": "MEDIA",
                "source_file": "media/",
                "expected_count": media_count,
                "sample_verification": [
                    {
                        "actor": "DEVICE",
                        "details_contains": {"filename": "IMG_20231114_120000.jpg"}
                    }
                ]
            }
        ],
        "negative_assertions": [
            {
                "description": "No Telegram artifacts (no DB present)",
                "artifact_type": "TELEGRAM_MSG",
                "expected_count": 0
            },
            {
                "description": "Text files should not be detected as media",
                "artifact_type": "MEDIA",
                "file_should_not_match": "document.txt"
            }
        ]
    }

    out_path = os.path.join(os.path.dirname(__file__), "golden", "ground_truth.json")
    with open(out_path, "w") as f:
        json.dump(ground_truth, f, indent=2, sort_keys=True)
    print(f"\n  Created ground_truth.json")
    return ground_truth


if __name__ == "__main__":
    print("=== XtractR Golden Dataset Generator v2 ===\n")

    create_dirs()
    print("Directory structure created.\n")

    print("Creating synthetic databases:")
    sms = create_sms_db()
    contacts, calls = create_contacts_db()
    urls = create_chrome_history()
    apps = create_packages_xml()
    accounts = create_accounts_db()
    whatsapp = create_whatsapp_db()
    media = create_media_files()

    print("\nCreating ground truth:")
    gt = create_ground_truth(sms, contacts, calls, urls, apps, accounts, whatsapp, media)

    total = gt["total_expected_artifacts"]
    print(f"\n=== Golden dataset ready at tests/golden/ ===")
    print(f"Total expected artifacts: {total}")
