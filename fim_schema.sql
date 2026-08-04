-- File Integrity Monitoring (FIM) schema
-- Apply against logdb: psql -h <host> -U hero -d logdb -f fim_schema.sql

CREATE TABLE IF NOT EXISTS public.fim_baseline (
    id            SERIAL PRIMARY KEY,
    file_path     TEXT NOT NULL UNIQUE,
    hash          TEXT,           -- NULL if file was deleted at time of last check
    mode          TEXT,           -- octal string, e.g. '0644'
    uid           INTEGER,
    mtime         TIMESTAMP,
    last_checked  TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS public.fim_events (
    id            SERIAL PRIMARY KEY,
    file_path     TEXT NOT NULL,
    event_type    TEXT NOT NULL,   -- 'modified' | 'added' | 'deleted' | 'permission_changed'
    old_hash      TEXT,
    new_hash      TEXT,
    old_mode      TEXT,
    new_mode      TEXT,
    detected_at   TIMESTAMP NOT NULL DEFAULT NOW(),
    severity      TEXT NOT NULL DEFAULT 'LOW'   -- uppercase, matches ssh_events/logs convention
);

CREATE INDEX IF NOT EXISTS idx_fim_events_detected_at ON public.fim_events (detected_at);
CREATE INDEX IF NOT EXISTS idx_fim_events_file_path ON public.fim_events (file_path);
