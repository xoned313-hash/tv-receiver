-- staged derived schema for the BAR materializer
-- safe to run multiple times

BEGIN;

CREATE TABLE IF NOT EXISTS materializer_state (
  id int PRIMARY KEY,
  last_raw_event_id bigint NOT NULL DEFAULT 0,
  updated_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO materializer_state (id, last_raw_event_id)
VALUES (1, 0)
ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS bars (
  dedup text PRIMARY KEY,
  uid text,
  raw_event_id bigint NOT NULL,
  received_at timestamptz NOT NULL,
  symbol text NOT NULL,
  tf_sec int NOT NULL,
  tf text,
  t_open_ms bigint,
  t_close_ms bigint,
  open double precision,
  high double precision,
  low double precision,
  close double precision,
  volume double precision,
  spot_close double precision,
  oi_close double precision,
  funding_rate double precision,
  premium_pct double precision,
  premium_idx double precision,
  basis double precision,
  basis_pct double precision,
  long_accounts double precision,
  short_accounts double precision,
  liq_buy double precision,
  liq_sell double precision,
  payload jsonb NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS bars_uid_uq
  ON bars (uid)
  WHERE uid IS NOT NULL;

CREATE INDEX IF NOT EXISTS bars_symbol_tf_close_idx
  ON bars (symbol, tf_sec, t_close_ms DESC);

CREATE INDEX IF NOT EXISTS bars_received_at_idx
  ON bars (received_at DESC);

COMMIT;
