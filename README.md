# tv-receiver

Contract-aligned TradingView ingress + staged BAR materializer for the telemetry ledger.

## Purpose

This repo hosts two services:

- `index.js` — the receiver that accepts TradingView webhook posts and persists redacted, idempotent raw rows into Postgres
- `materializer.js` — a staged worker that turns raw BAR payloads into a typed `bars` table for read-only analytics and MCP access

## Canonical document precedence

1. `docs/CONTRACT_P1.2_v2.4_integrated.txt`
2. `docs/PROJECT_INSTRUCTIONS_tv-receiver.txt`
3. `docs/PLAN_OF_ACTION_v2_no_corners.txt`
4. Implementation in this repo

If anything conflicts, the strictest interpretation that preserves auditability wins.

## Files

- `index.js` — receiver v3 / migration-safe hybrid ingress
- `materializer.js` — deterministic BAR materializer
- `sql/01_core_schema.sql` — core schema + zero-downtime upgrade path from legacy `raw_events`
- `sql/02_create_roles.sql` — least-privilege DB roles
- `sql/03_materializer_schema.sql` — staged derived schema for `bars` + materializer state
- `samples/test_bundle.json` — sample TradingView bundle payload
- `samples/test_single_record.json` — sample single BAR payload
- `docs/` — contract, plan, project instructions, producer reference, and change-control note

## Required environment variables

```text
DATABASE_URL=
DATABASE_CA_CERT=
WEBHOOK_SECRET=
RECEIVER_ENV=prod
```

Optional:

```text
PGSSL_INSECURE=0            # DEV only; forbidden in prod
MATERIALIZER_BATCH_SIZE=300
MATERIALIZER_IDLE_SLEEP_MS=5000
MATERIALIZER_ERROR_SLEEP_MS=5000
```

## Deploy order

1. Apply `sql/01_core_schema.sql` as an admin / migration role.
2. Apply `sql/02_create_roles.sql`.
3. Apply `sql/03_materializer_schema.sql` if you want the derived tables created before starting the worker.
4. Configure receiver env vars in the deployment platform.
5. Deploy the receiver.
6. Optionally deploy the materializer as a separate worker using the same repo.
7. Configure the TradingView alert:
   - Condition: `Any alert() function call`
   - Webhook URL: `https://<receiver-host>/tv?secret=<WEBHOOK_SECRET>`
   - Message: `{message}`
   - Frequency: `Once Per Bar Close`

## Verification checklist

### Receiver
- `GET /healthz` returns `ok=true` and `db_ok=true`
- a test `POST /tv` with `samples/test_bundle.json` inserts rows
- repeating the same `POST /tv` is idempotent on `uid`
- a bad or missing secret returns `401` and persists an `INGRESS_REJECT` row
- malformed JSON persists an `ERROR` row

### Materializer
- `node --check materializer.js`
- the worker reads raw BAR rows and inserts typed rows into `bars`
- MCP `tail_bars`, `latest_bar_per_stream`, and `bars_coverage` return useful data after materialization

## Security notes

- Do **not** put secrets in the JSON body. Use `?secret=...` only.
- Do **not** use `NODE_TLS_REJECT_UNAUTHORIZED=0` in prod.
- New receiver rows store `ip_hash` and `user_agent_hash` only.
- Existing historical legacy columns (`source_ip`, `user_agent`) are preserved only to avoid destructive migration during cutover.

## Migration stance

This handoff keeps the upgrade path safe:

- legacy `raw_events` columns are preserved so current data stays queryable
- contract-aligned columns are added for new ingestion
- `payload` is mirrored for compatibility while `payload_raw_redacted` becomes the canonical redacted raw payload field
- idempotency is enforced on `uid`
