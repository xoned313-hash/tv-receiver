-- tv-receiver least-privilege roles
-- Run as an admin / owner role.
-- Set passwords or connection methods out-of-band; this file only creates roles and grants.

BEGIN;

DO $$ BEGIN
  CREATE ROLE tv_ingress_writer LOGIN;
EXCEPTION
  WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
  CREATE ROLE tv_materializer_writer LOGIN;
EXCEPTION
  WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
  CREATE ROLE tv_mcp_reader LOGIN;
EXCEPTION
  WHEN duplicate_object THEN null;
END $$;

GRANT USAGE ON SCHEMA public TO tv_ingress_writer, tv_materializer_writer, tv_mcp_reader;

-- Receiver
GRANT SELECT, INSERT, UPDATE ON runs TO tv_ingress_writer;
GRANT SELECT, INSERT ON raw_events TO tv_ingress_writer;

-- Materializer raw access
GRANT SELECT ON runs TO tv_materializer_writer;
GRANT SELECT ON raw_events TO tv_materializer_writer;

-- MCP
GRANT SELECT ON runs TO tv_mcp_reader;
GRANT SELECT ON raw_events TO tv_mcp_reader;

-- Optional derived tables (grant only if they already exist)
DO $$
BEGIN
  IF to_regclass('public.materializer_state') IS NOT NULL THEN
    GRANT SELECT, INSERT, UPDATE ON materializer_state TO tv_materializer_writer;
    GRANT SELECT ON materializer_state TO tv_mcp_reader;
  END IF;

  IF to_regclass('public.bars') IS NOT NULL THEN
    GRANT SELECT, INSERT, UPDATE ON bars TO tv_materializer_writer;
    GRANT SELECT ON bars TO tv_mcp_reader;
  END IF;
END $$;

-- Sequences
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO tv_ingress_writer, tv_materializer_writer;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO tv_ingress_writer, tv_materializer_writer;

ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE ON TABLES TO tv_ingress_writer;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE ON TABLES TO tv_materializer_writer;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO tv_mcp_reader;

COMMIT;
