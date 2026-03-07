import express from "express";
import pg from "pg";
import crypto from "crypto";

const { Pool } = pg;

const app = express();
// TradingView may deliver JSON with application/json or text/plain.
// Parse raw text ourselves so we can persist parse failures instead of losing them in middleware.
app.use(express.text({ type: "*/*", limit: "2mb" }));

const PORT = parseInt(process.env.PORT || "8080", 10);
const RECEIVER_ENV = (process.env.RECEIVER_ENV || "prod").trim(); // prod|staging|dev
const WEBHOOK_SECRET = (process.env.WEBHOOK_SECRET || "").trim();
const DATABASE_URL_RAW = (process.env.DATABASE_URL || "").trim();
const DATABASE_CA_CERT = (process.env.DATABASE_CA_CERT || process.env.CA_CERT || "").trim();
const PGSSL_INSECURE = (process.env.PGSSL_INSECURE || "").trim() === "1";

const VALID_ROW_TYPES = new Set([
  "CONFIG",
  "BAR",
  "EVAL",
  "DECISION",
  "EVENT",
  "ENRICH_BAR",
  "HEARTBEAT",
  "ERROR",
  "INGRESS_REJECT",
  "QA_AUDIT",
  "RECONCILE",
  "MATERIALIZE_RUN",
  "REPLAY_REPORT",
  "SUPPRESS",
  "DUPLICATE"
]);

if (!DATABASE_URL_RAW) {
  console.error("FATAL: DATABASE_URL is not set");
  process.exit(1);
}
if (!WEBHOOK_SECRET) {
  console.error("FATAL: WEBHOOK_SECRET is not set (fail-closed)");
  process.exit(1);
}
if (PGSSL_INSECURE && RECEIVER_ENV === "prod") {
  console.error("FATAL: PGSSL_INSECURE=1 is forbidden when RECEIVER_ENV=prod");
  process.exit(1);
}
if (!DATABASE_CA_CERT && !PGSSL_INSECURE) {
  console.error("FATAL: DATABASE_CA_CERT is not set (TLS verification required)");
  process.exit(1);
}

function sha256Hex(s) {
  return crypto.createHash("sha256").update(s).digest("hex");
}

function stableStringify(x) {
  if (x === null || x === undefined) return "null";
  if (typeof x !== "object") return JSON.stringify(x);
  if (Array.isArray(x)) return "[" + x.map(stableStringify).join(",") + "]";
  const keys = Object.keys(x).sort();
  const parts = [];
  for (const k of keys) {
    parts.push(JSON.stringify(k) + ":" + stableStringify(x[k]));
  }
  return "{" + parts.join(",") + "}";
}

const REDACT_KEYS = new Set([
  "secret",
  "webhook_secret",
  "webhooksecret",
  "token",
  "authorization",
  "api_key",
  "apikey",
  "password"
]);

function redactDeep(obj) {
  if (obj === null || obj === undefined) return obj;
  if (Array.isArray(obj)) return obj.map(redactDeep);
  if (typeof obj !== "object") return obj;

  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    const lk = String(k).toLowerCase();
    if (REDACT_KEYS.has(lk)) {
      out[k] = "[REDACTED]";
    } else {
      out[k] = redactDeep(v);
    }
  }
  return out;
}

function scrubDbUrl(url) {
  if (!url) return "";
  try {
    const u = new URL(url);
    u.searchParams.delete("sslmode");
    return u.toString();
  } catch {
    return url.replace(/[?&]sslmode=[^&]+/gi, "");
  }
}

function pgSslConfig() {
  const pgsslmode = (process.env.PGSSLMODE || "").toLowerCase();
  if (pgsslmode === "disable") return false;

  if (DATABASE_CA_CERT) {
    return {
      rejectUnauthorized: true,
      ca: DATABASE_CA_CERT.replace(/\\n/g, "\n")
    };
  }

  if (PGSSL_INSECURE) {
    return { rejectUnauthorized: false };
  }

  return { rejectUnauthorized: true };
}

function getClientIp(req) {
  const xf = (req.headers["x-forwarded-for"] || "").toString();
  return xf.split(",")[0].trim() || req.socket?.remoteAddress || "";
}

function getUserAgent(req) {
  return (req.headers["user-agent"] || "").toString();
}

function formatDayIdUTC(ms) {
  const d = new Date(ms);
  return d.toISOString().slice(0, 10);
}

function formatDayIdLocal(ms, timeZone) {
  try {
    const fmt = new Intl.DateTimeFormat("en-CA", {
      timeZone,
      year: "numeric",
      month: "2-digit",
      day: "2-digit"
    });
    return fmt.format(new Date(ms));
  } catch {
    return formatDayIdUTC(ms);
  }
}

function sessionIdFromUTC(ms) {
  return "UTC_DAY_" + formatDayIdUTC(ms);
}

const REQUIRED_KEYS_COMMON = [
  "row_type",
  "schema_version",
  "schema_registry_hash",
  "producer",
  "uid",
  "seq",
  "run_id",
  "cfg_sig",
  "t_subject_ms",
  "t_event_ms",
  "env",
  "deployment_id",
  "exchange",
  "symbol",
  "tickerid",
  "instrument_type",
  "tf",
  "tf_sec"
];

function requiredKeysForRowType(rowType) {
  if (rowType === "EVAL") return REQUIRED_KEYS_COMMON.concat(["parent_uid"]);
  return REQUIRED_KEYS_COMMON;
}

function missingRequiredCount(rec, rowType) {
  const req = requiredKeysForRowType(rowType);
  let missing = 0;
  for (const k of req) {
    if (!(k in rec) || rec[k] === null || rec[k] === undefined || rec[k] === "") {
      missing += 1;
    }
  }
  return missing;
}

function producerIdFrom(rec) {
  const p = String(rec.producer || rec.producer_id || "").toUpperCase().trim();
  if (p === "A1M") return "A1M";
  if (p === "B1M") return "B1M";
  if (p === "ENRICHER") return "ENRICHER";
  if (p === "MATERIALIZER") return "MATERIALIZER";
  if (p === "QA_ENGINE") return "QA_ENGINE";
  if (p === "REPLAYER") return "REPLAYER";
  return "INGRESS";
}

function envFrom(rec) {
  const e = String(rec.env || "").toLowerCase().trim();
  if (e === "prod" || e === "staging" || e === "dev") return e;
  return RECEIVER_ENV === "staging" ? "staging" : (RECEIVER_ENV === "dev" ? "dev" : "prod");
}

function parseJsonBody(req) {
  const raw = typeof req.body === "string" ? req.body.trim() : "";
  if (!raw) return { ok: false, reason: "empty_body", raw: "" };
  try {
    return { ok: true, raw, json: JSON.parse(raw) };
  } catch (e) {
    return { ok: false, reason: "json_parse_failed", raw: raw.slice(0, 5000), error: e?.message || String(e) };
  }
}

const pool = new Pool({
  connectionString: scrubDbUrl(DATABASE_URL_RAW),
  ssl: pgSslConfig(),
  max: 5,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 10_000
});

async function dbSelfTest() {
  await pool.query("select 1 as ok");
  await pool.query("select 1 from runs limit 1");
  await pool.query("select 1 from raw_events limit 1");
}

async function upsertRun(client, {
  run_id,
  env,
  deployment_id,
  producer_id,
  timezone,
  started_at_ms,
  started_at_iso,
  cfg_sig,
  created_at_ms
}) {
  await client.query(
    `
    insert into runs (
      run_id, env, deployment_id, producer_id, timezone,
      started_at_ms, started_at_iso,
      first_cfg_sig, last_cfg_sig,
      created_at_ms
    )
    values ($1,$2,$3,$4,$5,$6,$7,$8,$8,$9)
    on conflict (run_id) do update set
      last_cfg_sig = excluded.last_cfg_sig,
      started_at_ms = least(runs.started_at_ms, excluded.started_at_ms),
      started_at_iso = case
        when runs.started_at_ms <= excluded.started_at_ms then runs.started_at_iso
        else excluded.started_at_iso
      end
    `,
    [
      run_id,
      env,
      deployment_id,
      producer_id,
      timezone,
      started_at_ms,
      started_at_iso,
      cfg_sig || null,
      created_at_ms
    ]
  );
}

async function insertRawEvent(client, row) {
  await client.query(
    `
    insert into raw_events (
      uid, row_type, parent_uid,
      run_id, cfg_sig,
      schema_version, schema_registry_hash,
      producer_id, deployment_id, env,
      exchange, symbol, tickerid, instrument_type, tf, tf_sec, seq,
      t_subject_ms, t_event_ms, t_received_ms, latency_ms,
      t_subject_iso, t_event_iso, timezone, day_id_utc, day_id_local, session_id,
      auth_ok, request_id, ip_hash, user_agent_hash,
      parse_ok, schema_match_ok, unknown_keys_count, missing_required_count,
      script_sha,
      payload_sha256, payload_size_bytes, payload_raw_redacted,
      payload, path, received_at, created_at_ms
    )
    values (
      $1,$2::row_type_t,$3,
      $4,$5,
      $6,$7,
      $8::producer_t,$9,$10::env_t,
      $11,$12,$13,$14,$15,$16,$17,
      $18,$19,$20,$21,
      $22,$23,$24,$25,$26,$27,
      $28,$29,$30,$31,
      $32,$33,$34,$35,
      $36,
      $37,$38,$39::jsonb,
      $40::jsonb,$41,$42,$43
    )
    on conflict (uid) do nothing
    `,
    [
      row.uid, row.row_type, row.parent_uid,
      row.run_id, row.cfg_sig,
      row.schema_version, row.schema_registry_hash,
      row.producer_id, row.deployment_id, row.env,
      row.exchange, row.symbol, row.tickerid, row.instrument_type, row.tf, row.tf_sec, row.seq,
      row.t_subject_ms, row.t_event_ms, row.t_received_ms, row.latency_ms,
      row.t_subject_iso, row.t_event_iso, row.timezone, row.day_id_utc, row.day_id_local, row.session_id,
      row.auth_ok, row.request_id, row.ip_hash, row.user_agent_hash,
      row.parse_ok, row.schema_match_ok, row.unknown_keys_count, row.missing_required_count,
      row.script_sha,
      row.payload_sha256, row.payload_size_bytes, JSON.stringify(row.payload_raw_redacted),
      JSON.stringify(row.payload_legacy_mirror),
      row.path,
      new Date(row.t_received_ms),
      row.created_at_ms
    ]
  );
}

function buildIngressFailureRecord({
  row_type,
  request_id,
  ip_hash,
  user_agent_hash,
  t_received_ms,
  reason,
  raw,
  path
}) {
  const z64 = "0".repeat(64);
  const payload_redacted = redactDeep({
    error_reason: reason,
    raw_payload: raw
  });
  const payload_str = stableStringify(payload_redacted);

  return {
    uid: `${row_type}|${request_id || t_received_ms}`,
    row_type,
    parent_uid: null,
    run_id: "RUN_UNKNOWN",
    cfg_sig: "CFG_UNKNOWN",
    schema_version: 0,
    schema_registry_hash: z64,
    producer_id: "INGRESS",
    deployment_id: "INGRESS",
    env: envFrom({ env: RECEIVER_ENV }),
    exchange: "UNKNOWN",
    symbol: "UNKNOWN",
    tickerid: "UNKNOWN",
    instrument_type: "UNKNOWN",
    tf: "UNKNOWN",
    tf_sec: 0,
    seq: 0,
    t_subject_ms: t_received_ms,
    t_event_ms: t_received_ms,
    t_received_ms,
    latency_ms: 0,
    t_subject_iso: new Date(t_received_ms).toISOString(),
    t_event_iso: new Date(t_received_ms).toISOString(),
    timezone: "UTC",
    day_id_utc: formatDayIdUTC(t_received_ms),
    day_id_local: formatDayIdUTC(t_received_ms),
    session_id: sessionIdFromUTC(t_received_ms),
    auth_ok: row_type !== "INGRESS_REJECT",
    request_id: request_id || null,
    ip_hash,
    user_agent_hash,
    parse_ok: false,
    schema_match_ok: false,
    unknown_keys_count: 0,
    missing_required_count: 0,
    script_sha: null,
    payload_sha256: sha256Hex(payload_str),
    payload_size_bytes: Buffer.byteLength(payload_str, "utf8"),
    payload_raw_redacted: payload_redacted,
    payload_legacy_mirror: payload_redacted,
    path,
    created_at_ms: t_received_ms
  };
}

async function persistFailureRow(row) {
  const client = await pool.connect();
  try {
    await client.query("begin");
    await upsertRun(client, {
      run_id: row.run_id,
      env: row.env,
      deployment_id: row.deployment_id,
      producer_id: row.producer_id,
      timezone: row.timezone,
      started_at_ms: row.t_subject_ms,
      started_at_iso: row.t_subject_iso,
      cfg_sig: row.cfg_sig,
      created_at_ms: row.created_at_ms
    });
    await insertRawEvent(client, row);
    await client.query("commit");
  } catch (e) {
    try {
      await client.query("rollback");
    } catch {
      // ignore
    }
    console.error("failed to persist failure row:", e);
  } finally {
    client.release();
  }
}

async function ingestLogicalRecord(client, {
  rec,
  auth_ok,
  request_id,
  ip_hash,
  user_agent_hash,
  t_received_ms,
  path
}) {
  const row_type = String(rec.row_type || "").trim();

  if (!VALID_ROW_TYPES.has(row_type)) {
    const err = buildIngressFailureRecord({
      row_type: auth_ok ? "ERROR" : "INGRESS_REJECT",
      request_id,
      ip_hash,
      user_agent_hash,
      t_received_ms,
      reason: `invalid_row_type:${row_type || "EMPTY"}`,
      raw: rec,
      path
    });
    await upsertRun(client, {
      run_id: err.run_id,
      env: err.env,
      deployment_id: err.deployment_id,
      producer_id: err.producer_id,
      timezone: err.timezone,
      started_at_ms: err.t_subject_ms,
      started_at_iso: err.t_subject_iso,
      cfg_sig: err.cfg_sig,
      created_at_ms: err.created_at_ms
    });
    await insertRawEvent(client, err);
    return;
  }

  const uid = String(rec.uid || "").trim();
  if (!uid) {
    const err = buildIngressFailureRecord({
      row_type: auth_ok ? "ERROR" : "INGRESS_REJECT",
      request_id,
      ip_hash,
      user_agent_hash,
      t_received_ms,
      reason: "missing_uid",
      raw: rec,
      path
    });
    await upsertRun(client, {
      run_id: err.run_id,
      env: err.env,
      deployment_id: err.deployment_id,
      producer_id: err.producer_id,
      timezone: err.timezone,
      started_at_ms: err.t_subject_ms,
      started_at_iso: err.t_subject_iso,
      cfg_sig: err.cfg_sig,
      created_at_ms: err.created_at_ms
    });
    await insertRawEvent(client, err);
    return;
  }

  const env = envFrom(rec);
  const producer_id = producerIdFrom(rec);
  const run_id = String(rec.run_id || "RUN_UNKNOWN").trim() || "RUN_UNKNOWN";
  const cfg_sig = String(rec.cfg_sig || "CFG_UNKNOWN").trim() || "CFG_UNKNOWN";
  const deployment_id = String(rec.deployment_id || "UNKNOWN").trim() || "UNKNOWN";
  const exchange = String(rec.exchange || "UNKNOWN").trim() || "UNKNOWN";
  const symbol = String(rec.symbol || "UNKNOWN").trim() || "UNKNOWN";
  const tickerid = String(rec.tickerid || "UNKNOWN").trim() || "UNKNOWN";
  const instrument_type = String(rec.instrument_type || "UNKNOWN").trim() || "UNKNOWN";
  const tf = String(rec.tf || "UNKNOWN").trim() || "UNKNOWN";
  const tf_sec = Number.isFinite(rec.tf_sec) ? Number(rec.tf_sec) : parseInt(String(rec.tf_sec || "0"), 10) || 0;
  const seq = Number.isFinite(rec.seq) ? Number(rec.seq) : parseInt(String(rec.seq || "0"), 10) || 0;
  const schema_version = Number.isFinite(rec.schema_version) ? Number(rec.schema_version) : parseInt(String(rec.schema_version || "0"), 10) || 0;
  const schema_registry_hash = String(rec.schema_registry_hash || "0".repeat(64)).trim() || "0".repeat(64);
  const t_subject_ms = Number.isFinite(rec.t_subject_ms) ? Number(rec.t_subject_ms) : parseInt(String(rec.t_subject_ms || "0"), 10) || 0;
  const t_event_ms = Number.isFinite(rec.t_event_ms) ? Number(rec.t_event_ms) : parseInt(String(rec.t_event_ms || "0"), 10) || 0;
  const timezone = String(rec.timezone_id || rec.timezone || "UTC").trim() || "UTC";
  const day_id_utc = formatDayIdUTC(t_subject_ms || t_received_ms);
  const day_id_local = formatDayIdLocal(t_subject_ms || t_received_ms, timezone);
  const session_id = sessionIdFromUTC(t_subject_ms || t_received_ms);
  const rec_redacted = redactDeep(rec);
  const payload_str = stableStringify(rec_redacted);
  const payload_sha256 = sha256Hex(payload_str);
  const payload_size_bytes = Buffer.byteLength(payload_str, "utf8");
  const missing_required_count = missingRequiredCount(rec, row_type);
  const schema_match_ok = missing_required_count === 0;
  const unknown_keys_count = 0;
  const final_row_type = auth_ok ? row_type : "INGRESS_REJECT";

  await upsertRun(client, {
    run_id,
    env,
    deployment_id,
    producer_id,
    timezone,
    started_at_ms: t_subject_ms || t_received_ms,
    started_at_iso: new Date(t_subject_ms || t_received_ms).toISOString(),
    cfg_sig,
    created_at_ms: t_received_ms
  });

  const row = {
    uid,
    row_type: final_row_type,
    parent_uid: rec.parent_uid ? String(rec.parent_uid) : null,
    run_id,
    cfg_sig,
    schema_version,
    schema_registry_hash,
    producer_id,
    deployment_id,
    env,
    exchange,
    symbol,
    tickerid,
    instrument_type,
    tf,
    tf_sec,
    seq,
    t_subject_ms: t_subject_ms || t_received_ms,
    t_event_ms: t_event_ms || t_received_ms,
    t_received_ms,
    latency_ms: t_received_ms - (t_event_ms || t_received_ms),
    t_subject_iso: new Date(t_subject_ms || t_received_ms).toISOString(),
    t_event_iso: new Date(t_event_ms || t_received_ms).toISOString(),
    timezone,
    day_id_utc,
    day_id_local,
    session_id,
    auth_ok: Boolean(auth_ok),
    request_id,
    ip_hash,
    user_agent_hash,
    parse_ok: true,
    schema_match_ok,
    unknown_keys_count,
    missing_required_count,
    script_sha: rec.script_sha ? String(rec.script_sha) : null,
    payload_sha256,
    payload_size_bytes,
    payload_raw_redacted: rec_redacted,
    payload_legacy_mirror: rec_redacted,
    path,
    created_at_ms: t_received_ms
  };

  await insertRawEvent(client, row);
}

async function handleWebhook(req, res) {
  const t_received_ms = Date.now();
  const request_id = crypto.randomUUID();
  const ip_hash = sha256Hex(getClientIp(req) || "");
  const user_agent_hash = sha256Hex(getUserAgent(req) || "");
  const auth_ok = String(req.query.secret || "") === WEBHOOK_SECRET;
  const path = req.path;

  const parsed = parseJsonBody(req);
  if (!parsed.ok) {
    const row = buildIngressFailureRecord({
      row_type: auth_ok ? "ERROR" : "INGRESS_REJECT",
      request_id,
      ip_hash,
      user_agent_hash,
      t_received_ms,
      reason: parsed.reason,
      raw: parsed.raw,
      path
    });
    await persistFailureRow(row);
    return res.status(auth_ok ? 400 : 401).json({ ok: false, error: parsed.reason, request_id });
  }

  const body = parsed.json;
  const bodyStr = parsed.raw;
  if (/"secret"\s*:/.test(bodyStr) || /"webhook_secret"\s*:/.test(bodyStr) || /"token"\s*:/.test(bodyStr)) {
    const row = buildIngressFailureRecord({
      row_type: auth_ok ? "ERROR" : "INGRESS_REJECT",
      request_id,
      ip_hash,
      user_agent_hash,
      t_received_ms,
      reason: "secret_in_body_forbidden",
      raw: "[REDACTED_AT_INGRESS]",
      path
    });
    await persistFailureRow(row);
    return res.status(auth_ok ? 400 : 401).json({ ok: false, error: "secret_in_body_forbidden", request_id });
  }

  const client = await pool.connect();
  try {
    await client.query("begin");

    if (body && body.bundle_type === "TV_ALERT_BUNDLE" && Array.isArray(body.records)) {
      for (const rec of body.records) {
        await ingestLogicalRecord(client, { rec, auth_ok, request_id, ip_hash, user_agent_hash, t_received_ms, path });
      }
    } else if (body && typeof body === "object") {
      await ingestLogicalRecord(client, { rec: body, auth_ok, request_id, ip_hash, user_agent_hash, t_received_ms, path });
    } else {
      const row = buildIngressFailureRecord({
        row_type: auth_ok ? "ERROR" : "INGRESS_REJECT",
        request_id,
        ip_hash,
        user_agent_hash,
        t_received_ms,
        reason: "non_json_body",
        raw: body,
        path
      });
      await upsertRun(client, {
        run_id: row.run_id,
        env: row.env,
        deployment_id: row.deployment_id,
        producer_id: row.producer_id,
        timezone: row.timezone,
        started_at_ms: row.t_subject_ms,
        started_at_iso: row.t_subject_iso,
        cfg_sig: row.cfg_sig,
        created_at_ms: row.created_at_ms
      });
      await insertRawEvent(client, row);
    }

    await client.query("commit");

    if (!auth_ok) {
      return res.status(401).json({ ok: false, error: "unauthorized", request_id });
    }
    return res.json({ ok: true, request_id });
  } catch (e) {
    try {
      await client.query("rollback");
    } catch {
      // ignore
    }
    console.error("ingest failed:", e);

    const row = buildIngressFailureRecord({
      row_type: auth_ok ? "ERROR" : "INGRESS_REJECT",
      request_id,
      ip_hash,
      user_agent_hash,
      t_received_ms,
      reason: "ingest_exception:" + (e?.message || String(e)),
      raw: "[REDACTED_AT_INGRESS]",
      path
    });
    await persistFailureRow(row);

    return res.status(auth_ok ? 500 : 401).json({ ok: false, error: auth_ok ? "ingest_failed" : "unauthorized", request_id });
  } finally {
    client.release();
  }
}

app.get("/healthz", async (req, res) => {
  try {
    await pool.query("select 1 as ok");
    const c = await pool.query("select count(*)::bigint as n from raw_events");
    const last = await pool.query("select max(t_received_ms)::bigint as last_ms from raw_events");
    res.json({
      ok: true,
      env: RECEIVER_ENV,
      db_ok: true,
      raw_events: {
        count: c.rows[0].n,
        last_received_ms: last.rows[0].last_ms || null
      },
      now: new Date().toISOString()
    });
  } catch (e) {
    res.status(500).json({ ok: false, db_ok: false, error: e.message });
  }
});

app.post("/tv", handleWebhook);
app.post("/webhook", handleWebhook);

dbSelfTest()
  .then(() => {
    app.listen(PORT, "0.0.0.0", () => console.log("listening on", PORT));
  })
  .catch((e) => {
    console.error("FATAL: DB self-test failed. Did you apply migrations?", e);
    process.exit(1);
  });
