# CHANGE_CONTROL — 2026-03-06 — tv-receiver receiver v3 + migration-safe RAW spine

## Goal
Bring `tv-receiver` to a contract-aligned, audit-grade running state without destroying existing raw history.

## Why
- align ingress with `CONTRACT_P1.2_v2.4_integrated.txt`
- remove insecure / non-compliant patterns (body secrets, raw IP persistence for new rows, TLS bypasses)
- preserve current live data while adding the fields needed for idempotent RAW ingestion and staged materialization

## Constraints
- no destructive migration of current `raw_events`
- no `NODE_TLS_REJECT_UNAUTHORIZED=0` in prod
- no secrets committed in docs / code / samples
- new receiver rows must use `uid` idempotency and persist auth / parse failures

## Affected components
- `index.js`
- `materializer.js`
- `README.md`
- `sql/01_core_schema.sql`
- `sql/02_create_roles.sql`
- `sql/03_materializer_schema.sql`
- `docs/*`

## Forward impact
- existing legacy `raw_events` rows remain queryable
- new rows gain contract-aligned fields
- materializer can consume both legacy bundle rows and new per-record rows
- MCP server can read `bars` and raw metadata without needing public export endpoints

## Acceptance tests
- `node --check index.js`
- `node --check materializer.js`
- `GET /healthz` returns `db_ok=true`
- test `POST /tv` inserts rows
- duplicate `POST /tv` remains idempotent on `uid`
- bad secret returns `401` and persists `INGRESS_REJECT`
- malformed JSON persists `ERROR`

## Rollback plan
- redeploy the prior receiver/materializer image if necessary
- keep the expanded schema in place (do not drop new columns)
- if needed, stop the new receiver and continue reading historical rows while investigating
