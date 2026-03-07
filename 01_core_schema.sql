-- tv-receiver core schema migration
-- 2026-03-06
-- Goal:
--   zero-downtime upgrade path from a legacy minimal raw_events table to a contract-aligned RAW spine
--
-- Notes:
--   - preserves legacy columns (id, received_at, path, source_ip, user_agent, payload)
--   - adds contract-required columns for new ingestion
--   - enforces idempotency on uid via a unique index
--   - keeps run_id + seq unique for rows where both are present

BEGIN;

DO $$ BEGIN
  CREATE TYPE env_t AS ENUM ('prod','staging','dev');
EXCEPTION
  WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
  CREATE TYPE producer_t AS ENUM ('A1M','B1M','ENRICHER','MATERIALIZER','QA_ENGINE','REPLAYER','INGRESS');
EXCEPTION
  WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
  CREATE TYPE row_type_t AS ENUM (
    'CONFIG','BAR','EVAL','DECISION','EVENT','ENRICH_BAR',
    'HEARTBEAT','ERROR','INGRESS_REJECT','QA_AUDIT','RECONCILE',
    'MATERIALIZE_RUN','REPLAY_REPORT','SUPPRESS','DUPLICATE'
  );
EXCEPTION
  WHEN duplicate_object THEN null;
END $$;

CREATE TABLE IF NOT EXISTS runs (
  run_id        text PRIMARY KEY,
  env           env_t NOT NULL,
  deployment_id text NOT NULL,
  producer_id   producer_t NOT NULL,
  timezone      text NOT NULL,
  started_at_ms  bigint NOT NULL,
  started_at_iso text NOT NULL,
  first_cfg_sig  text,
  last_cfg_sig   text,
  status        text NOT NULL DEFAULT 'OPEN',
  created_at_ms bigint NOT NULL
);

-- Legacy-compatible RAW table:
-- if raw_events already exists, preserve it and add contract fields.
CREATE TABLE IF NOT EXISTS raw_events (
  id bigserial PRIMARY KEY,
  received_at timestamptz NOT NULL DEFAULT now(),
  path text,
  source_ip text,
  user_agent text,
  payload jsonb
);

ALTER TABLE raw_events ADD COLUMN IF NOT EXISTS uid text;
ALTER TABLE raw_events ADD COLUMN IF NOT EXISTS row_type row_type_t;
ALTER TABLE raw_events ADD COLUMN IF NOT EXISTS parent_uid text;

ALTER TABLE raw_events ADD COLUMN IF NOT EXISTS run_id text;
ALTER TABLE raw_events ADD COLUMN IF NOT EXISTS cfg_sig text;

ALTER TABLE raw_events ADD COLUMN IF NOT EXISTS schema_version int;
ALTER TABLE raw_events ADD COLUMN IF NOT EXISTS schema_registry_hash text;

ALTER TABLE raw_events ADD COLUMN IF NOT EXISTS producer_id producer_t;
ALTER TABLE raw_events ADD COLUMN IF NOT EXISTS deployment_id text;
ALTER TABLE raw_events ADD COLUMN IF NOT EXISTS env env_t;

ALTER TABLE raw_events ADD COLUMN IF NOT EXISTS exchange text;
ALTER TABLE raw_events ADD COLUMN IF NOT EXISTS symbol text;
ALTER TABLE raw_events ADD COLUMN IF NOT EXISTS tickerid text;
ALTER TABLE raw_events ADD COLUMN IF NOT EXISTS instrument_type text;
ALTER TABLE raw_events ADD COLUMN IF NOT EXISTS tf text;
ALTER TABLE raw_events ADD COLUMN IF NOT EXISTS tf_sec int;
ALTER TABLE raw_events ADD COLUMN IF NOT EXISTS seq bigint;

ALTER TABLE raw_events ADD COLUMN IF NOT EXISTS t_subject_ms bigint;
ALTER TABLE raw_events ADD COLUMN IF NOT EXISTS t_event_ms bigint;
ALTER TABLE raw_events ADD COLUMN IF NOT EXISTS t_received_ms bigint;
ALTER TABLE raw_events ADD COLUMN IF NOT EXISTS latency_ms bigint;

ALTER TABLE raw_events ADD COLUMN IF NOT EXISTS t_subject_iso text;
ALTER TABLE raw_events ADD COLUMN IF NOT EXISTS t_event_iso text;
ALTER TABLE raw_events ADD COLUMN IF NOT EXISTS timezone text;
ALTER TABLE raw_events ADD COLUMN IF NOT EXISTS day_id_utc text;
ALTER TABLE raw_events ADD COLUMN IF NOT EXISTS day_id_local text;
ALTER TABLE raw_events ADD COLUMN IF NOT EXISTS session_id text;

ALTER TABLE raw_events ADD COLUMN IF NOT EXISTS auth_ok boolean;
ALTER TABLE raw_events ADD COLUMN IF NOT EXISTS request_id text;
ALTER TABLE raw_events ADD COLUMN IF NOT EXISTS ip_hash text;
ALTER TABLE raw_events ADD COLUMN IF NOT EXISTS user_agent_hash text;

ALTER TABLE raw_events ADD COLUMN IF NOT EXISTS parse_ok boolean;
ALTER TABLE raw_events ADD COLUMN IF NOT EXISTS schema_match_ok boolean;
ALTER TABLE raw_events ADD COLUMN IF NOT EXISTS unknown_keys_count int;
ALTER TABLE raw_events ADD COLUMN IF NOT EXISTS missing_required_count int;

ALTER TABLE raw_events ADD COLUMN IF NOT EXISTS script_sha text;

ALTER TABLE raw_events ADD COLUMN IF NOT EXISTS payload_sha256 text;
ALTER TABLE raw_events ADD COLUMN IF NOT EXISTS payload_size_bytes int;
ALTER TABLE raw_events ADD COLUMN IF NOT EXISTS payload_raw_redacted jsonb;

ALTER TABLE raw_events ADD COLUMN IF NOT EXISTS created_at_ms bigint;

-- Foreign key only if run_id is present.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM information_schema.table_constraints
    WHERE table_name = 'raw_events'
      AND constraint_name = 'raw_events_run_id_fkey'
  ) THEN
    ALTER TABLE raw_events
    ADD CONSTRAINT raw_events_run_id_fkey
    FOREIGN KEY (run_id) REFERENCES runs(run_id);
  END IF;
EXCEPTION
  WHEN duplicate_object THEN null;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS raw_uid_uq
  ON raw_events (uid)
  WHERE uid IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS raw_run_seq_uq
  ON raw_events (run_id, seq)
  WHERE run_id IS NOT NULL AND seq IS NOT NULL;

CREATE INDEX IF NOT EXISTS raw_rowtype_day_idx
  ON raw_events (row_type, day_id_utc);

CREATE INDEX IF NOT EXISTS raw_symbol_tf_day_idx
  ON raw_events (symbol, tf_sec, day_id_utc);

CREATE INDEX IF NOT EXISTS raw_received_idx
  ON raw_events (received_at DESC);

COMMIT;
