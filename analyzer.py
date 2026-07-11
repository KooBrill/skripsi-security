import time
import json
import sqlite3
import requests
import os
import re
import ipaddress

from datetime import datetime, timedelta

# ── Konfigurasi ──────────────────────────────────────────────
LOG_PATH = "/var/log/nginx/shared/threat_alert.log"
DB_PATH = "/app/db/threats.db"
WEBHOOK_URL = os.getenv("N8N_WEBHOOK_URL", "")
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "")
SCORE_LIMIT = 100
RETENTION_DAYS = 30

# ═══════════════════════════════════════════════════════════
# Bobot Ancaman: Dimensi 1 — Target (20+ endpoint)
# ═══════════════════════════════════════════════════════════
TARGET_WEIGHTS = {
    # Tier 1: Kritis (50-60 poin)
    ".env": 60,
    ".env.local": 60,
    ".env.production": 60,
    "wp-config.php": 60,
    "config.php": 60,
    "id_rsa": 60,
    ".git/config": 55,
    ".git/HEAD": 55,
    ".sql": 55,
    ".bak": 50,
    "phpMyAdmin": 50,
    "c99.php": 60,
    "r57.php": 60,
    
    # Tier 2: Tinggi (35-49 poin)
    ".git": 45,
    ".svn": 45,
    "Dockerfile": 45,
    "docker-compose.yml": 45,
    "aws-credentials": 45,
    ".pem": 45,
    ".key": 45,
    "xmlrpc.php": 45,
    "graphql": 40,
    "swagger": 40,
    "api-docs": 40,
    
    # Tier 3: Sedang (25-34 poin)
    "wp-admin": 35,
    "wp-login.php": 35,
    "administrator": 35,
    "admin": 30,
    "panel": 30,
    "phpinfo.php": 30,
    "server-status": 30,
    "debug": 30,
    "actuator": 30,
    "jenkins": 30,
    
    # Tier 4: Rendah (15-24 poin)
    "api/v1": 20,
    "rest/api": 20,
    "soap": 20,
    "webmail": 20,
    "grafana": 20,
    "kibana": 20,
}

# ═══════════════════════════════════════════════════════════
# Bobot Ancaman: Dimensi 2 — Alat (25+ tools)
# ═══════════════════════════════════════════════════════════
UA_WEIGHTS = {
    # Offensive Tools (40-50 poin)
    "sqlmap": 50,
    "nikto": 45,
    "nmap": 45,
    "masscan": 45,
    "nuclei": 45,
    "metasploit": 50,
    "burpsuite": 45,
    "zap": 40,
    "arachni": 40,
    
    # Recon Tools (30-39 poin)
    "dirbuster": 35,
    "gobuster": 35,
    "dirb": 35,
    "wfuzz": 35,
    "ffuf": 35,
    "subfinder": 30,
    "amass": 30,
    "theharvester": 30,
    
    # Automation (20-29 poin)
    "python-requests": 25,
    "python-urllib": 25,
    "curl": 20,
    "wget": 20,
    "httpie": 20,
    "postmanruntime": 15,
    
    # Bots (10-19 poin)
    "zgrab": 25,
    "semrushbot": 15,
    "ahrefsbot": 15,
    "mj12bot": 15,
}

# ═══════════════════════════════════════════════════════════
# Bobot Tambahan: Human Behavior & Evasion
# ═══════════════════════════════════════════════════════════
HUMAN_BEHAVIOR_WEIGHTS = {
    "manual_browser_probe": 25,  # Browser asli akses honeypot
    "encoded_uri": 30,           # WAF bypass
    "path_traversal": 45,        # Directory traversal
}

# ── Helper: Cek IP Privat ───────────────────────────────────
def is_private_ip(ip_str: str) -> bool:
    """Cek apakah IP adalah IP Lokal/NAT (bukan dari internet)"""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_reserved
    except ValueError:
        return True

# ── Setup Database SQLite dengan WAL Mode ───────────────────
def init_db():
    con = sqlite3.connect(DB_PATH, timeout=10.0)
    con.execute("PRAGMA journal_mode=WAL;")
    con.execute("PRAGMA busy_timeout=5000;")
    con.execute("""
        CREATE TABLE IF NOT EXISTS ip_scores (
            ip TEXT PRIMARY KEY,
            score INTEGER DEFAULT 0,
            last_seen TEXT,
            reported INTEGER DEFAULT 0
        )
    """)
    con.commit()
    return con

# ── Hitung Skor Ancaman Multi-Dimensi ──────────────────────
def calculate_score(uri: str, user_agent: str, is_tool: int) -> int:
    score = 0
    is_human_target = False
    
    # Dimensi 1: Target
    for target, weight in TARGET_WEIGHTS.items():
        if target in uri:
            score += weight
            is_human_target = True
            break
    
    # Dimensi 2: Tool/Bot
    if is_tool == 1:
        score += 30
    else:
        for tool, weight in UA_WEIGHTS.items():
            if tool.lower() in user_agent.lower():
                score += weight
                break
    
    # Dimensi 3: Human Browser Probe
    human_browsers = ['chrome', 'firefox', 'safari', 'edge', 'opera']
    is_real_browser = any(browser in user_agent.lower() for browser in human_browsers)
    if is_real_browser and is_human_target:
        score += HUMAN_BEHAVIOR_WEIGHTS["manual_browser_probe"]
    
    # Dimensi 4: WAF Bypass (URL Encoding)
    if re.search(r'%[0-9a-fA-F]{2}', uri):
        score += HUMAN_BEHAVIOR_WEIGHTS["encoded_uri"]
    
    # Dimensi 5: Path Traversal
    if re.search(r'\.\.[/\\]', uri) or re.search(r'%2[eE]%2[eE]', uri):
        score += HUMAN_BEHAVIOR_WEIGHTS["path_traversal"]
    
    return score

# ── Update Skor IP di SQLite ────────────────────────────────
def update_ip_score(con, ip: str, delta: int) -> dict:
    now = datetime.utcnow().isoformat()
    con.execute("""
        INSERT INTO ip_scores (ip, score, last_seen, reported)
        VALUES (?, ?, ?, 0)
        ON CONFLICT(ip) DO UPDATE SET
            score = score + excluded.score,
            last_seen = excluded.last_seen
    """, (ip, delta, now))
    con.commit()
    row = con.execute(
        "SELECT score, reported FROM ip_scores WHERE ip = ?", (ip,)
    ).fetchone()
    return {"score": row[0], "reported": row[1]}

# ── Kirim ke n8n ────────────────────────────────────────────
def trigger_webhook(payload: dict):
    if not WEBHOOK_URL:
        print(f"[WARN] WEBHOOK_URL belum di-set. Skip.")
        return
    try:
        headers = {"Content-Type": "application/json"}
        if WEBHOOK_SECRET:
            headers["X-Webhook-Secret"] = WEBHOOK_SECRET
        resp = requests.post(
            WEBHOOK_URL,
            json=payload,
            headers=headers,
            timeout=5
        )
        print(f"[WEBHOOK] type={payload['type']} ip={payload['ip_address']} → {resp.status_code}")
    except requests.RequestException as e:
        print(f"[ERROR] Gagal kirim webhook: {e}")

# ── Hapus Data Lama ─────────────────────────────────────────
def cleanup_old_records(con):
    cutoff = (datetime.utcnow() - timedelta(days=RETENTION_DAYS)).isoformat()
    con.execute("DELETE FROM ip_scores WHERE last_seen < ?", (cutoff,))
    con.commit()

# ── Baca Log Real-time ──────────────────────────────────────
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

# ── Main Loop ───────────────────────────────────────────────
def main():
    print("[START] Python Analyzer aktif...")
    con = init_db()
    cleanup_counter = 0
    
    for raw_line in tail_log(LOG_PATH):
        try:
            entry = json.loads(raw_line)
            ip = entry.get("ip", "")
            uri = entry.get("uri", "")
            user_agent = entry.get("ua", "")
            is_tool = int(entry.get("tool", 0))
            now = datetime.utcnow().isoformat()
            
            if not ip:
                continue
            
            # 🛡️ Skip IP Privat/NAT
            if is_private_ip(ip):
                continue
            
            # Hitung skor
            delta = calculate_score(uri, user_agent, is_tool)
            result = update_ip_score(con, ip, delta)
            print(f"[LOG] {ip} | uri={uri} | +{delta} poin | Total: {result['score']}")
            
            # Kirim setiap hit ke n8n
            trigger_webhook({
                "type": "hit",
                "ip_address": ip,
                "uri": uri,
                "user_agent": user_agent,
                "score_delta": delta,
                "total_score": result["score"],
                "is_tool": is_tool == 1,
                "detected_at": now
            })
            
            # Kalau skor >= 100 dan belum pernah diblokir
            if result["score"] >= SCORE_LIMIT and result["reported"] == 0:
                print(f"[ALERT] {ip} melewati batas skor {SCORE_LIMIT} → BLOKIR")
                trigger_webhook({
                    "type": "ban",
                    "ip_address": ip,
                    "final_score": result["score"],
                    "banned_at": now
                })
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
