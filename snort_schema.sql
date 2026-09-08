-- Snort IDS integration schema
-- Apply against logdb: psql -h <host> -U hero -d logdb -f snort_schema.sql

CREATE TABLE IF NOT EXISTS public.snort_alerts (
    id             SERIAL PRIMARY KEY,
    captured_at    TIMESTAMP NOT NULL DEFAULT NOW(),
    gid            INTEGER,
    sid            INTEGER,
    rev            INTEGER,
    message        TEXT,
    classification TEXT,
    priority       INTEGER,        -- Snort's own 1-4 scale (1 = highest)
    protocol       TEXT,
    src_ip         TEXT,
    src_port       INTEGER,
    dst_ip         TEXT,
    dst_port       INTEGER,
    severity       TEXT NOT NULL DEFAULT 'LOW',  -- mapped from priority, uppercase (matches fim_events/ssh_events)
    raw            TEXT
);

CREATE INDEX IF NOT EXISTS idx_snort_alerts_captured_at ON public.snort_alerts (captured_at);
CREATE INDEX IF NOT EXISTS idx_snort_alerts_src_ip ON public.snort_alerts (src_ip);
