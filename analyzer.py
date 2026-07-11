import time
import json
import sqlite3
import requests
import redis
import os
import re
import ipaddress
import threading
from datetime import datetime, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# ── Konfigurasi ──────────────────────────────────────────────
LOG_PATH       = "/var/log/nginx/shared/threat_alert.log"
DB_PATH        = "/app/db/threats.db"
WEBHOOK_URL    = os.getenv("N8N_WEBHOOK_URL", "")
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "")
REDIS_HOST     = os.getenv("REDIS_HOST", "redis")
REDIS_PORT     = int(os.getenv("REDIS_PORT", "6379"))
SCORE_LIMIT    = 100
RETENTION_DAYS = 30

# ═══════════════════════════════════════════════════════════
# Progressive Ban Duration
# ban_count: 1 → 2 hari | 2 → 5 hari | 3 → 10 hari | 4+ → 30 hari
# ban_count: 5+ → ESKALASI ke UFW permanen via n8n
# ═══════════════════════════════════════════════════════════
BAN_SCHEDULE = {
    1: 60 * 60 * 24 * 2,
    2: 60 * 60 * 24 * 5,
    3: 60 * 60 * 24 * 10,
}
BAN_MAX = 60 * 60 * 24 * 30
PERMANENT_BAN_THRESHOLD = 5

def get_ban_duration(ban_count: int) -> int:
    return BAN_SCHEDULE.get(ban_count, BAN_MAX)

def get_ban_label(ban_count: int) -> str:
    labels = {1: "2 hari", 2: "5 hari", 3: "10 hari"}
    return labels.get(ban_count, "30 hari")

# ═══════════════════════════════════════════════════════════
# Bobot Ancaman: Dimensi 1 — Target (30+ endpoint)
# ═══════════════════════════════════════════════════════════
TARGET_WEIGHTS = {
    ".env": 60, ".env.local": 60, ".env.production": 60,
    "wp-config.php": 60, "config.php": 60, "id_rsa": 60,
    ".git/config": 55, ".git/HEAD": 55, ".sql": 55, ".bak": 50,
    "phpMyAdmin": 50, "c99.php": 60, "r57.php": 60,
    ".git": 45, ".svn": 45, "Dockerfile": 45, "docker-compose.yml": 45,
    "aws-credentials": 45, ".pem": 45, ".key": 45, "xmlrpc.php": 45,
    "graphql": 40, "swagger": 40, "api-docs": 40,
    "wp-admin": 35, "wp-login.php": 35, "administrator": 35,
    "admin": 30, "panel": 30, "phpinfo.php": 30, "server-status": 30,
    "debug": 30, "actuator": 30, "jenkins": 30,
    "api/v1": 20, "rest/api": 20, "soap": 20, "webmail": 20,
    "grafana": 20, "kibana": 20,
}

# ═══════════════════════════════════════════════════════════
# Bobot Ancaman: Dimensi 2 — Alat (25+ tools)
# ═══════════════════════════════════════════════════════════
UA_WEIGHTS = {
    "sqlmap": 50, "nikto": 45, "nmap": 45, "masscan": 45, "nuclei": 45,
    "metasploit": 50, "burpsuite": 45, "zap": 40, "arachni": 40,
    "dirbuster": 35, "gobuster": 35, "dirb": 35, "wfuzz": 35, "ffuf": 35,
    "subfinder": 30, "amass": 30, "theharvester": 30,
    "python-requests": 25, "python-urllib": 25, "curl": 20, "wget": 20,
    "httpie": 20, "postmanruntime": 15,
    "zgrab": 25, "semrushbot": 15, "ahrefsbot": 15, "mj12bot": 15,
}

HUMAN_BEHAVIOR_WEIGHTS = {
    "manual_browser_probe": 25,
    "encoded_uri": 30,
    "path_traversal": 45,
}

# ── Helper: Cek IP Privat ──────────────────────────────────────
def is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_reserved
    except ValueError:
        return True

# ── Koneksi Redis ───────────────────────────────────────────────
def get_redis():
    return redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

# ── Ban IP ke Redis (Progressive) ───────────────────────────────
def ban_ip(ip: str, score: int) -> dict:
    r = get_redis()
    ban_count_key = f"ban_count:{ip}"
    ban_count = r.incr(ban_count_key)

    duration   = get_ban_duration(ban_count)
    label      = get_ban_label(ban_count)
    expires_at = datetime.utcnow() + timedelta(seconds=duration)

    ban_data = {
        "ip":         ip,
        "score":      score,
        "ban_count":  ban_count,
        "duration":   label,
        "banned_at":  datetime.utcnow().isoformat(),
        "expires_at": expires_at.isoformat()
    }

    r.setex(f"banned:{ip}", duration, json.dumps(ban_data))
    print(f"[BAN] {ip} | ban ke-{ban_count} | durasi: {label} | skor: {score}")
    return ban_data

# ── Cek apakah IP banned ────────────────────────────────────────
def is_banned(ip: str):
    r = get_redis()
    data = r.get(f"banned:{ip}")
    if data:
        info = json.loads(data)
        ttl = r.ttl(f"banned:{ip}")
        info["ttl_hours"] = round(ttl / 3600, 1) if ttl > 0 else 0
        return info
    return None

# ── Mini HTTP Server untuk Nginx auth_request ────────────────────
class BanCheckHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/check":
            params = parse_qs(parsed.query)
            ip = params.get("ip", [""])[0]
            if not ip:
                self.send_response(400)
                self.end_headers()
                return
            ban_info = is_banned(ip)
            if ban_info:
                self.send_response(403)
                self.send_header("Content-Type", "application/json")
                self.send_header("X-Ban-Count",    str(ban_info.get("ban_count", 1)))
                self.send_header("X-Ban-Duration", ban_info.get("duration", ""))
                self.send_header("X-Ban-TTL",      str(ban_info.get("ttl_hours", 0)))
                self.end_headers()
                self.wfile.write(json.dumps(ban_info).encode())
            else:
                self.send_response(200)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass

def start_ban_server():
    server = HTTPServer(("0.0.0.0", 8080), BanCheckHandler)
    print("[BAN SERVER] Jalan di port 8080")
    server.serve_forever()

# ── Setup Database SQLite (WAL Mode) ─────────────────────────────
def init_db():
    con = sqlite3.connect(DB_PATH, timeout=10.0)
    con.execute("PRAGMA journal_mode=WAL;")
    con.execute("PRAGMA busy_timeout=5000;")
    con.execute("""
        CREATE TABLE IF NOT EXISTS ip_scores (
            ip         TEXT PRIMARY KEY,
            score      INTEGER DEFAULT 0,
            last_seen  TEXT,
            reported   INTEGER DEFAULT 0
        )
    """)
    con.commit()
    return con

# ── Hitung Skor Ancaman Multi-Dimensi ────────────────────────────
def calculate_score(uri: str, user_agent: str, is_tool: int) -> int:
    score = 0
    is_human_target = False

    for target, weight in TARGET_WEIGHTS.items():
        if target in uri:
            score += weight
            is_human_target = True
            break

    if is_tool == 1:
        score += 30
    else:
        for tool, weight in UA_WEIGHTS.items():
            if tool.lower() in user_agent.lower():
                score += weight
                break

    human_browsers = ['chrome', 'firefox', 'safari', 'edge', 'opera']
    is_real_browser = any(b in user_agent.lower() for b in human_browsers)
    if is_real_browser and is_human_target:
        score += HUMAN_BEHAVIOR_WEIGHTS["manual_browser_probe"]

    if re.search(r'%[0-9a-fA-F]{2}', uri):
        score += HUMAN_BEHAVIOR_WEIGHTS["encoded_uri"]

    if re.search(r'\.\.[/\\]', uri) or re.search(r'%2[eE]%2[eE]', uri):
        score += HUMAN_BEHAVIOR_WEIGHTS["path_traversal"]

    return score

# ── Update Skor IP di SQLite ─────────────────────────────────────
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

def reset_ip_score(con, ip: str):
    con.execute("UPDATE ip_scores SET score = 0, reported = 0 WHERE ip = ?", (ip,))
    con.commit()
    print(f"[RESET] Skor {ip} direset setelah ban")

# ── Kirim ke n8n ──────────────────────────────────────────────────
def trigger_webhook(payload: dict):
    if not WEBHOOK_URL:
        print(f"[WARN] WEBHOOK_URL belum di-set. Skip.")
        return
    try:
        headers = {"Content-Type": "application/json"}
        if WEBHOOK_SECRET:
            headers["X-Webhook-Secret"] = WEBHOOK_SECRET
        resp = requests.post(WEBHOOK_URL, json=payload, headers=headers, timeout=5)
        print(f"[WEBHOOK] type={payload.get('type')} ip={payload.get('ip_address', '-')} → {resp.status_code}")
    except requests.RequestException as e:
        print(f"[ERROR] Gagal kirim webhook: {e}")

# ── Log Sistem untuk Jurnal/Audit ────────────────────────────────
def log_system_event(event_type: str, component: str, message: str,
                      metadata: dict = None, severity: str = "info"):
    """Kirim log sistem ke Supabase via n8n untuk keperluan jurnal/audit."""
    if not WEBHOOK_URL:
        return
    try:
        payload = {
            "type":       "system_log",
            "event_type": event_type,
            "component":  component,
            "message":    message,
            "metadata":   metadata or {},
            "severity":   severity,
            "created_at": datetime.utcnow().isoformat()
        }
        headers = {"Content-Type": "application/json"}
        if WEBHOOK_SECRET:
            headers["X-Webhook-Secret"] = WEBHOOK_SECRET
        requests.post(WEBHOOK_URL, json=payload, headers=headers, timeout=5)
    except requests.RequestException:
        pass  # Jangan sampai logging gagal menghentikan proses utama

# ── Hapus Data Lama ───────────────────────────────────────────────
def cleanup_old_records(con):
    cutoff = (datetime.utcnow() - timedelta(days=RETENTION_DAYS)).isoformat()
    con.execute("DELETE FROM ip_scores WHERE last_seen < ?", (cutoff,))
    con.commit()

# ── Baca Log Real-time ─────────────────────────────────────────────
def tail_log(filepath: str):
    while not os.path.exists(filepath):
        print(f"[WAIT] File {filepath} belum ada, coba lagi 2 detik...")
        time.sleep(2)
    print(f"[OK] File {filepath} ditemukan, mulai baca log...")
    log_system_event("log_file_found", "python-analyzer",
                      f"File log honeypot ditemukan: {filepath}", severity="info")
    with open(filepath, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if line:
                yield line.strip()
            else:
                time.sleep(0.5)

# ── Main Loop ────────────────────────────────────────────────────────
def main():
    print("[START] Python Analyzer + Ban Server aktif...")
    log_system_event("startup", "python-analyzer",
                      "Sistem Python Analyzer dimulai", severity="info")

    ban_thread = threading.Thread(target=start_ban_server, daemon=True)
    ban_thread.start()

    con = init_db()
    cleanup_counter = 0

    for raw_line in tail_log(LOG_PATH):
        try:
            entry      = json.loads(raw_line)
            ip         = entry.get("ip", "")
            uri        = entry.get("uri", "")
            user_agent = entry.get("ua", "")
            is_tool    = int(entry.get("tool", 0))
            now        = datetime.utcnow().isoformat()

            if not ip:
                continue

            if is_private_ip(ip):
                continue

            delta  = calculate_score(uri, user_agent, is_tool)
            result = update_ip_score(con, ip, delta)

            print(f"[LOG] {ip} | uri={uri} | +{delta} poin | Total: {result['score']}")

            trigger_webhook({
                "type":        "hit",
                "ip_address":  ip,
                "uri":         uri,
                "user_agent":  user_agent,
                "score_delta": delta,
                "total_score": result["score"],
                "is_tool":     is_tool == 1,
                "detected_at": now
            })

            if result["score"] >= SCORE_LIMIT and result["reported"] == 0:
                ban_info = ban_ip(ip, result["score"])
                reset_ip_score(con, ip)

                con.execute("UPDATE ip_scores SET reported = 1 WHERE ip = ?", (ip,))
                con.commit()

                is_permanent = ban_info["ban_count"] >= PERMANENT_BAN_THRESHOLD

                trigger_webhook({
                    "type":         "ban_permanent" if is_permanent else "ban",
                    "ip_address":   ip,
                    "final_score":  result["score"],
                    "ban_count":    ban_info["ban_count"],
                    "duration":     "PERMANEN" if is_permanent else ban_info["duration"],
                    "banned_at":    now,
                    "expires_at":   None if is_permanent else ban_info["expires_at"]
                })

                log_system_event(
                    "ban_executed", "python-analyzer",
                    f"IP {ip} diblokir (ban ke-{ban_info['ban_count']})",
                    metadata={"ip": ip, "ban_count": ban_info["ban_count"],
                              "duration": ban_info["duration"], "score": result["score"]},
                    severity="warning"
                )

                if is_permanent:
                    print(f"[ESCALATION] {ip} sudah {ban_info['ban_count']}x kena ban → eskalasi ke UFW PERMANEN")
                    log_system_event(
                        "ban_escalated", "python-analyzer",
                        f"IP {ip} dieskalasi ke blokir permanen setelah {ban_info['ban_count']} pelanggaran",
                        metadata={"ip": ip, "ban_count": ban_info["ban_count"]},
                        severity="critical"
                    )

        except json.JSONDecodeError:
            print(f"[WARN] Bukan JSON valid, skip: {raw_line[:80]}")
        except Exception as e:
            print(f"[ERROR] {e}")
            log_system_event(
                "processing_error", "python-analyzer",
                f"Error saat memproses log: {str(e)}",
                severity="error"
            )

        cleanup_counter += 1
        if cleanup_counter >= 1000:
            cleanup_old_records(con)
            cleanup_counter = 0

if __name__ == "__main__":
    main()
