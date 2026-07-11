-- ═══════════════════════════════════════════════════════
-- TABEL log_system — untuk keperluan jurnal/audit trail
-- Jalankan ini di Supabase SQL Editor
-- ═══════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS log_system (
  id          BIGSERIAL PRIMARY KEY,
  event_type  TEXT NOT NULL,
  component   TEXT NOT NULL,
  message     TEXT NOT NULL,
  metadata    JSONB,
  severity    TEXT DEFAULT 'info',
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_log_system_created_at ON log_system (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_log_system_event_type  ON log_system (event_type);
CREATE INDEX IF NOT EXISTS idx_log_system_severity     ON log_system (severity);

ALTER TABLE log_system ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow anon select" ON log_system FOR SELECT USING (true);
CREATE POLICY "Allow service insert" ON log_system FOR INSERT WITH CHECK (true);

-- ═══════════════════════════════════════════════════════
-- Update tabel log_banned — tambah kolom progressive ban
-- ═══════════════════════════════════════════════════════

ALTER TABLE log_banned ADD COLUMN IF NOT EXISTS ban_count  INTEGER DEFAULT 1;
ALTER TABLE log_banned ADD COLUMN IF NOT EXISTS duration   TEXT;
ALTER TABLE log_banned ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
