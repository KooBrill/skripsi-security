import time
import json
import sqlite3
import requests
import os
import ipaddress
from datetime import datetime, timedelta

# ── Konfigurasi ──────────────────────────────────────────────
LOG_PATH       = "/var/log/nginx/shared/threat_alert.log"
DB_PATH        = "/app/db/threats.db"
WEBHOOK_URL    = os.getenv("N8N_WEBHOOK_URL", "")
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "")
SUPABASE_URL   = os.getenv("SUPABASE_URL", "")      # https://xxx.supabase.co
SUPABASE_KEY   = os.getenv("SUPABASE_KEY", "")      # service_role key
SCORE_LIMIT    = 100
RETENTION_DAYS = 30

# Bobot ancaman: Dimensi 1 — Target
TARGET_WEIGHTS = {
    ".env":         50,
    ".git":         40,
    "phpMyAdmin":   35,
    "wp-admin":     30,
    "wp-login.php": 30,
    "admin":        20,
}

# Bobot ancaman: Dimensi 2 — Alat
UA_WEIGHTS = {
    "sqlmap":          50,
    "nikto":           35,
    "nmap":            30,
    "masscan":         30,
    "nuclei":          45,
    "zgrab":           25,
    "dirbuster":       35,
    "gobuster":        35,
    "python-requests": 10,
    "curl":             5,
}

# Bobot ancaman: Dimensi 3 — Human Heuristics
BROWSER_SIGNATURES = ["chrome", "firefox", "safari", "edge", "opera"]
HUMAN_PROBE_WEIGHT = 25

# Bobot ancaman: Dimensi 4 — WAF Bypass / Evasion
WAF_BYPASS_PATTERNS = [
    "%2e",      # URL-encoded dot (.)
    "%2f",      # URL-encoded slash (/)
    "%252e",    # Double-encoded dot
    "%252f",    # Double-encoded slash
    "..%2f",    # Path traversal variant
    "%00",      # Null byte injection
    "..;/",     # Tomcat path traversal
]
WAF_BYPASS_WEIGHT = 30

# ── Filter IP Privat/NAT ─────────────────────────────────────
def is_private_ip(ip: str) -> bool:
    """Abaikan IP privat (192.168.x.x, 10.x.x.x, 172.16-31.x.x, 127.x.x.x)
    untuk mencegah false positive dari jaringan internal."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

# ── Setup Database ────────────────────────────────────────────
def init_db():
    con = sqlite3.connect(DB_PATH)
    con.execute("""
        CREATE TABLE IF NOT EXISTS ip_scores (
            ip         TEXT PRIMARY KEY,
            score      INTEGER DEFAULT 0,
            last_seen  TEXT,
            reported   INTEGER DEFAULT 0
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS threat_logs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            ip          TEXT NOT NULL,
            method      TEXT,
            uri         TEXT,
            status      INTEGER,
            user_agent  TEXT,
            is_tool     INTEGER DEFAULT 0,
            score_delta INTEGER DEFAULT 0,
            score_total INTEGER DEFAULT 0
        )
    """)
    con.commit()
    return con

# ── Simpan Log Individual (SQLite) ────────────────────────────
def insert_log(con, entry: dict, delta: int, total: int):
    """Simpan setiap request honeypot ke SQLite lokal (backup)."""
    con.execute("""
        INSERT INTO threat_logs (timestamp, ip, method, uri, status, user_agent, is_tool, score_delta, score_total)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        entry.get("time", datetime.utcnow().isoformat()),
        entry.get("ip", ""),
        entry.get("method", ""),
        entry.get("uri", ""),
        entry.get("status", 0),
        entry.get("ua", ""),
        int(entry.get("tool", 0)),
        delta,
        total,
    ))
    con.commit()

# ── Push Log ke Supabase ──────────────────────────────────────
def push_to_supabase(entry: dict, delta: int, total: int):
    """Kirim log ke Supabase agar bisa dilihat dari browser."""
    if not SUPABASE_URL or not SUPABASE_KEY:
        return
    try:
        resp = requests.post(
            f"{SUPABASE_URL}/rest/v1/threat_logs",
            headers={
                "apikey": SUPABASE_KEY,
                "Authorization": f"Bearer {SUPABASE_KEY}",
                "Content-Type": "application/json",
                "Prefer": "return=minimal",
            },
            json={
                "timestamp":   entry.get("time", datetime.utcnow().isoformat()),
                "ip":          entry.get("ip", ""),
                "method":      entry.get("method", ""),
                "uri":         entry.get("uri", ""),
                "status":      entry.get("status", 0),
                "user_agent":  entry.get("ua", ""),
                "is_tool":     int(entry.get("tool", 0)),
                "score_delta": delta,
                "score_total": total,
            },
            timeout=5,
        )
        if resp.status_code not in (200, 201):
            print(f"[WARN] Supabase insert gagal: {resp.status_code} {resp.text[:100]}")
    except requests.RequestException as e:
        print(f"[WARN] Supabase error (skip): {e}")

# ── Hitung Skor Ancaman (Multi-Dimensi) ──────────────────────
def calculate_score(uri: str, user_agent: str, is_tool: int) -> int:
    score = 0
    ua_lower = user_agent.lower()
    uri_lower = uri.lower()

    # Dimensi 1: Target Weight
    for target, weight in TARGET_WEIGHTS.items():
        if target in uri:
            score += weight
            break

    # Dimensi 2: Tool Detection
    is_known_tool = False
    if is_tool == 1:
        score += 30
        is_known_tool = True
    else:
        for tool, weight in UA_WEIGHTS.items():
            if tool.lower() in ua_lower:
                score += weight
                is_known_tool = True
                break

    # Dimensi 3: Human Heuristics
    # Browser asli mengakses honeypot = manual probing
    is_browser = any(sig in ua_lower for sig in BROWSER_SIGNATURES)
    if is_browser and not is_known_tool:
        score += HUMAN_PROBE_WEIGHT

    # Dimensi 4: WAF Bypass / Evasion Detection
    if any(pattern in uri_lower for pattern in WAF_BYPASS_PATTERNS):
        score += WAF_BYPASS_WEIGHT

    return score

# ── Update Skor IP ────────────────────────────────────────────
def update_ip_score(con, ip: str, delta: int) -> dict:
    now = datetime.utcnow().isoformat()
    con.execute("""
        INSERT INTO ip_scores (ip, score, last_seen, reported)
        VALUES (?, ?, ?, 0)
        ON CONFLICT(ip) DO UPDATE SET
            score     = score + excluded.score,
            last_seen = excluded.last_seen
    """, (ip, delta, now))
    con.commit()
    row = con.execute(
        "SELECT score, reported FROM ip_scores WHERE ip = ?", (ip,)
    ).fetchone()
    return {"score": row[0], "reported": row[1]}

# ── Kirim Webhook ke n8n ──────────────────────────────────────
def trigger_webhook(ip: str, score: int):
    if not WEBHOOK_URL:
        print(f"[WARN] WEBHOOK_URL belum di-set. Skip untuk {ip}")
        return
    try:
        headers = {}
        if WEBHOOK_SECRET:
            headers["X-Webhook-Secret"] = WEBHOOK_SECRET
        resp = requests.post(WEBHOOK_URL, json={
            "ip_address": ip,
            "score":      score,
            "timestamp":  datetime.utcnow().isoformat()
        }, headers=headers, timeout=5)
        print(f"[ALERT] Webhook terkirim untuk {ip} (skor: {score}) → {resp.status_code}")
    except requests.RequestException as e:
        print(f"[ERROR] Gagal kirim webhook: {e}")

# ── Hapus Data Lama ──────────────────────────────────────────
def cleanup_old_records(con):
    cutoff = (datetime.utcnow() - timedelta(days=RETENTION_DAYS)).isoformat()
    con.execute("DELETE FROM ip_scores WHERE last_seen < ?", (cutoff,))
    con.execute("DELETE FROM threat_logs WHERE timestamp < ?", (cutoff,))
    con.commit()

# ── Baca Log Real-time ───────────────────────────────────────
def tail_log(filepath: str):
    while not os.path.exists(filepath):
        print(f"[WAIT] File {filepath} belum ada, coba lagi 2 detik...")
        time.sleep(2)
    print(f"[OK] File {filepath} ditemukan, mulai baca log...")
    with open(filepath, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if line:
                yield line.strip()
            else:
                time.sleep(0.5)

# ── Main Loop ────────────────────────────────────────────────
def main():
    print("[START] Python Analyzer aktif...")
    con = init_db()
    cleanup_counter = 0

    for raw_line in tail_log(LOG_PATH):
        try:
            entry      = json.loads(raw_line)
            ip         = entry.get("ip", "")
            uri        = entry.get("uri", "")
            user_agent = entry.get("ua", "")
            is_tool    = int(entry.get("tool", 0))

            if not ip:
                continue

            # Filter IP Privat/NAT — cegah false positive internal
            if is_private_ip(ip):
                continue

            delta  = calculate_score(uri, user_agent, is_tool)
            result = update_ip_score(con, ip, delta)

            # Simpan log individual
            insert_log(con, entry, delta, result["score"])  # SQLite (backup lokal)
            push_to_supabase(entry, delta, result["score"])  # Supabase (bisa cek dari browser)

            print(f"[LOG] {ip} | +{delta} poin | Total: {result['score']}")

            if result["score"] >= SCORE_LIMIT and result["reported"] == 0:
                trigger_webhook(ip, result["score"])
                con.execute("UPDATE ip_scores SET reported = 1 WHERE ip = ?", (ip,))
                con.commit()

        except json.JSONDecodeError:
            print(f"[WARN] Bukan JSON valid, skip: {raw_line[:80]}")
        except Exception as e:
            print(f"[ERROR] {e}")

        cleanup_counter += 1
        if cleanup_counter >= 1000:
            cleanup_old_records(con)
            cleanup_counter = 0

if __name__ == "__main__":
    main()
