import time
import json
import sqlite3
import requests
import os
from datetime import datetime, timedelta

# ── Konfigurasi ──────────────────────────────────────────────
LOG_PATH       = "/var/log/nginx/shared/threat_alert.log"
DB_PATH        = "/app/db/threats.db"
WEBHOOK_URL    = os.getenv("N8N_WEBHOOK_URL", "")
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "")
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
    "sqlmap":          40,
    "nikto":           35,
    "nmap":            30,
    "masscan":         30,
    "nuclei":          30,
    "zgrab":           25,
    "dirbuster":       25,
    "gobuster":        25,
    "python-requests": 10,
    "curl":             5,
}

# ── Setup Database SQLite ─────────────────────────────────────
# SQLite = memori sementara untuk akumulasi skor per IP
# Data final dikirim ke Supabase via n8n webhook
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
    con.commit()
    return con

# ── Hitung Skor Ancaman ───────────────────────────────────────
def calculate_score(uri: str, user_agent: str, is_tool: int) -> int:
    score = 0
    for target, weight in TARGET_WEIGHTS.items():
        if target in uri:
            score += weight
            break
    if is_tool == 1:
        score += 30
    else:
        for tool, weight in UA_WEIGHTS.items():
            if tool.lower() in user_agent.lower():
                score += weight
                break
    return score

# ── Update Skor IP di SQLite ──────────────────────────────────
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

# ── Kirim ke n8n ─────────────────────────────────────────────
# Payload dibedakan:
# type "hit"  → insert ke tabel log_layer7 (setiap serangan)
# type "ban"  → insert ke tabel log_banned (saat blokir)
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

# ── Hapus Data Lama dari SQLite ───────────────────────────────
def cleanup_old_records(con):
    cutoff = (datetime.utcnow() - timedelta(days=RETENTION_DAYS)).isoformat()
    con.execute("DELETE FROM ip_scores WHERE last_seen < ?", (cutoff,))
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
            now        = datetime.utcnow().isoformat()

            if not ip:
                continue

            # Hitung skor untuk hit ini
            delta  = calculate_score(uri, user_agent, is_tool)
            result = update_ip_score(con, ip, delta)

            print(f"[LOG] {ip} | uri={uri} | +{delta} poin | Total: {result['score']}")

            # Kirim setiap hit ke n8n → insert ke log_layer7
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

            # Kalau skor >= 100 dan belum pernah diblokir → kirim ban
            if result["score"] >= SCORE_LIMIT and result["reported"] == 0:
                print(f"[ALERT] {ip} melewati batas skor {SCORE_LIMIT} → BLOKIR")

                trigger_webhook({
                    "type":        "ban",
                    "ip_address":  ip,
                    "final_score": result["score"],
                    "banned_at":   now
                })

                # Tandai sudah dilaporkan di SQLite
                con.execute(
                    "UPDATE ip_scores SET reported = 1 WHERE ip = ?", (ip,)
                )
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
