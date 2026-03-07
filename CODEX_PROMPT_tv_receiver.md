# CODEX PROMPT — tv-receiver

You are working in the `tv-receiver` repository.

Use the files in `/codex-handoff/2026-03-06/tv-receiver` as the **replacement base** and execute this prompt exactly.

## Objective

Bring the repo to a **migration-safe, contract-aligned receiver v3 state** with:
- secure TradingView ingress
- idempotent RAW persistence
- zero-downtime upgrade path from the current legacy `raw_events` table
- a staged BAR materializer that can read both legacy bundle rows and new per-record rows

## Canonical precedence

1. `docs/CONTRACT_P1.2_v2.4_integrated.txt`
2. `docs/PROJECT_INSTRUCTIONS_tv-receiver.txt`
3. `docs/PLAN_OF_ACTION_v2_no_corners.txt`
4. Existing repo code

If anything conflicts, take the strictest interpretation that preserves auditability and replayability.

## Required changes

1. Replace `index.js` with the provided receiver implementation, or a stricter equivalent that still satisfies the same contract.
2. Replace `materializer.js` with the provided staged materializer, or a stricter equivalent that:
   - reads legacy bundle rows from `payload.records[]`
   - reads new per-record BAR rows from `payload_raw_redacted`
   - writes typed `bars` rows idempotently
3. Add / update:
   - `.env.example`
   - `.gitignore`
   - `README.md`
   - `sql/01_core_schema.sql`
   - `sql/02_create_roles.sql`
   - `sql/03_materializer_schema.sql`
   - `docs/CONTRACT_P1.2_v2.4_integrated.txt`
   - `docs/PROJECT_INSTRUCTIONS_tv-receiver.txt`
   - `docs/PLAN_OF_ACTION_v2_no_corners.txt`
   - `docs/B1M_TRUTH.txt`
   - `docs/CHANGE_CONTROL_2026-03-06_receiver_v3.md`
   - `samples/test_bundle.json`
   - `samples/test_single_record.json`

## Non-negotiable constraints

- **Do not** keep or introduce live secrets anywhere in the repo.
- **Do not** accept secrets in JSON bodies.
- **Do not** use `NODE_TLS_REJECT_UNAUTHORIZED=0` in prod docs or code.
- **Do not** store raw source IP for new receiver rows.
- **Do not** remove the current legacy `raw_events` columns during this pass.
- **Do not** require a destructive migration.
- **Do not** expose raw data via public debug/export routes in the final receiver. Use `/healthz` + MCP for verification instead.

## Required implementation stance

- Receiver must serve:
  - `POST /tv`
  - `POST /webhook`
  - `GET /healthz`
- Receiver must:
  - verify DB TLS with `DATABASE_CA_CERT`
  - validate `?secret=...`
  - persist auth failures / parse failures as `INGRESS_REJECT` or `ERROR`
  - compute `payload_sha256`, `payload_size_bytes`, `ip_hash`, `user_agent_hash`
  - compute `day_id_utc`, `day_id_local`, `session_id`
  - compute `missing_required_count` and `schema_match_ok`
  - upsert `runs`
  - insert `raw_events` with `ON CONFLICT (uid) DO NOTHING`
- Materializer must remain deterministic and idempotent.

## Verification checklist to run

1. `node --check index.js`
2. `node --check materializer.js`
3. Confirm SQL files exist and are internally consistent.
4. Ensure the README includes exact deploy + verification steps.
5. If a test DB is available in the sandbox, run:
   - core schema migration
   - materializer schema migration
   - a sample `POST /tv` using `samples/test_bundle.json`
   - a duplicate `POST /tv`
   - a bad-secret `POST /tv`
   and include the observed outputs in the PR description.
   If no DB is available, say that runtime validation was not executed and keep the PR explicit about that.

## Required PR output

Open a PR from a new branch and include:

- a concise summary of what changed
- explicit list of files changed
- migration notes
- verification results
- rollback plan
- the contents of `docs/CHANGE_CONTROL_2026-03-06_receiver_v3.md`

## Minimal safe diff rule

Keep the diff as small as possible while still satisfying the above. Do not refactor unrelated code.
