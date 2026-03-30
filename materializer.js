
import pg from "pg";
import crypto from "crypto";

const { Pool } = pg;

const DATABASE_URL_RAW = (process.env.DATABASE_URL || "").trim();
const CA_CERT = (process.env.CA_CERT || process.env.DATABASE_CA_CERT || "").trim();
const PGSSL_INSECURE = (process.env.PGSSL_INSECURE || "").trim() === "1";

if (!DATABASE_URL_RAW) {
  console.error("FATAL: DATABASE_URL is not set");
  process.exit(1);
}
if (!CA_CERT && !PGSSL_INSECURE) {
  console.error("FATAL: DATABASE_CA_CERT (or CA_CERT) is required unless PGSSL_INSECURE=1 for DEV only");
  process.exit(1);
}

function scrubDbUrl(url) {
  if (!url) return "";
  try {
    const u = new URL(url);
    u.searchParams.delete("sslmode");
    u.searchParams.delete("sslrootcert");
    return u.toString();
  } catch {
    return url.replace(/[?&](sslmode|sslrootcert)=[^&]+/gi, "");
  }
}

function pgSslConfig() {
  const pgsslmode = (process.env.PGSSLMODE || "").toLowerCase();
  if (pgsslmode === "disable") return false;

  if (CA_CERT) {
    return {
      rejectUnauthorized: true,
      ca: CA_CERT.replace(/\\n/g, "\n"),
    };
  }

  if (PGSSL_INSECURE) {
    return { rejectUnauthorized: false };
  }

  return { rejectUnauthorized: true };
}

const pool = new Pool({
  connectionString: scrubDbUrl(DATABASE_URL_RAW),
  ssl: pgSslConfig(),
  max: 10,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 10_000,
});

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function sha256Hex(value) {
  const h = crypto.createHash("sha256");
  h.update(typeof value === "string" ? value : String(value ?? ""));
  return h.digest("hex");
}

function stableStringify(x) {
  if (x === null || x === undefined) return "null";
  if (typeof x !== "object") return JSON.stringify(x);
  if (Array.isArray(x)) return "[" + x.map((v) => stableStringify(v)).join(",") + "]";
  const keys = Object.keys(x).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + stableStringify(x[k])).join(",") + "}";
}

function asObject(maybeJson) {
  if (maybeJson == null) return null;
  if (typeof maybeJson === "object") return maybeJson;
  if (typeof maybeJson === "string") {
    try {
      return JSON.parse(maybeJson);
    } catch {
      return null;
    }
  }
  return null;
}

function cloneJson(value) {
  return value == null ? value : JSON.parse(JSON.stringify(value));
}

function isMissing(v) {
  return v === null || v === undefined || (typeof v === "string" && v.trim() === "");
}

function isNonEmptyString(v) {
  return typeof v === "string" && v.trim().length > 0;
}

function toInt(v) {
  if (isMissing(v)) return null;
  const n = Number(v);
  return Number.isFinite(n) ? Math.trunc(n) : null;
}

function toFloat(v) {
  if (isMissing(v)) return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

function parseTfSec(tf) {
  if (!isNonEmptyString(tf)) return null;
  const s = tf.trim().toUpperCase();
  const m = s.match(/^(\d+)(S|M|H|D|W|MO)?$/);
  if (!m) return null;
  const n = parseInt(m[1], 10);
  const unit = m[2] || "M";
  if (unit === "S") return n;
  if (unit === "M") return n * 60;
  if (unit === "H") return n * 3600;
  if (unit === "D") return n * 86400;
  if (unit === "W") return n * 604800;
  if (unit === "MO") return n * 2592000;
  return null;
}

function inferProducerId(rec) {
  const raw = String(rec.producer_id || rec.producer || rec.stream_id || "").toUpperCase().trim();
  if (raw.includes("A1M")) return "A1M";
  if (raw.includes("B1M")) return "B1M";
  if (raw.includes("B2M")) return "B2M";
  if (raw.includes("B3M")) return "B3M";
  if (raw.includes("MATERIALIZER")) return "MATERIALIZER";
  if (raw.includes("INGRESS")) return "INGRESS";
  return "INGRESS";
}

function inferStreamId(rec) {
  if (isNonEmptyString(rec.stream_id)) return String(rec.stream_id).trim();
  const joined = `${rec.producer || ""}|${rec.event_type || ""}|${rec.log_tag || ""}`.toUpperCase();
  if (joined.includes("B2M")) return "B2M_AP";
  if (joined.includes("B3M")) return "B3M_PIVOTS";
  if (joined.includes("B1M")) return "B1M";
  if (joined.includes("A1M")) return "A1M";
  return null;
}

function normalizeCfgSig(rec) {
  const raw = isNonEmptyString(rec.cfg_sig_raw)
    ? String(rec.cfg_sig_raw).trim()
    : isNonEmptyString(rec.cfg_sig)
      ? String(rec.cfg_sig).trim()
      : null;

  let full = rec.cfg_sig_full;
  if (full && typeof full === "object") {
    full = stableStringify(full);
  }
  if (isNonEmptyString(full)) {
    let canonical = String(full).trim();
    try {
      canonical = stableStringify(JSON.parse(canonical));
    } catch {
      // keep as-is
    }
    return {
      cfg_sig_raw: raw,
      cfg_sig_full: canonical,
      cfg_sig_sha256: sha256Hex(canonical),
    };
  }

  if (isNonEmptyString(rec.cfg_sig_sha256) && /^[a-f0-9]{64}$/i.test(String(rec.cfg_sig_sha256).trim())) {
    return {
      cfg_sig_raw: raw,
      cfg_sig_full: null,
      cfg_sig_sha256: String(rec.cfg_sig_sha256).trim().toLowerCase(),
    };
  }

  if (isNonEmptyString(raw) && /^[a-f0-9]{64}$/i.test(raw)) {
    return {
      cfg_sig_raw: raw.toLowerCase(),
      cfg_sig_full: null,
      cfg_sig_sha256: raw.toLowerCase(),
    };
  }

  if (isNonEmptyString(raw)) {
    return {
      cfg_sig_raw: raw,
      cfg_sig_full: null,
      cfg_sig_sha256: sha256Hex(raw),
    };
  }

  return { cfg_sig_raw: null, cfg_sig_full: null, cfg_sig_sha256: null };
}

const CONTEXT_KEYS = [
  "json_schema_version", "wide_schema_version", "csv_schema_version",
  "env", "deployment_id", "timezone_id", "timezone", "schema_registry_version", "schema_registry_hash",
  "script_id", "script_sha", "stream_id", "universe_id", "alert_tag",
  "run_id", "cfg_sig", "cfg_sig_raw", "cfg_sig_full", "cfg_sig_sha256",
  "exchange", "symbol", "symbol_native", "instrument_type", "tickerid", "tf", "tf_sec",
  "source_family", "symbol_role", "asset_class", "research_cluster",
  "underlying_code", "underlying_name", "underlying_group", "quote_code",
  "price_quote", "contracts_def", "event_type"
];

function fillMissing(target, source, keys = CONTEXT_KEYS) {
  if (!source) return target;
  for (const key of keys) {
    if (isMissing(target[key]) && !isMissing(source[key])) {
      target[key] = source[key];
    }
  }
  return target;
}

function expandLogicalRecords(payload) {
  const body = asObject(payload);
  if (!body) return [];

  const bundleVersion = toInt(body.bundle_version);
  const bundleType = isNonEmptyString(body.bundle_type) ? String(body.bundle_type).trim() : null;
  const bundleSentAtMs = toInt(body.sent_at_ms);

  let records = [];
  if (Array.isArray(body.records)) {
    records = body.records.map((rec) => asObject(rec)).filter(Boolean);
  } else if (body && typeof body === "object") {
    records = [body];
  }

  const configRec = records.find((rec) => String(rec.row_type || "").toUpperCase() === "CONFIG") || null;
  const barsByUid = new Map();
  const barsByCanonical = new Map();
  for (const rec of records) {
    if (String(rec.row_type || "").toUpperCase() === "BAR") {
      if (isNonEmptyString(rec.uid)) barsByUid.set(String(rec.uid), rec);
      if (isNonEmptyString(rec.bar_uid_canonical)) barsByCanonical.set(String(rec.bar_uid_canonical), rec);
    }
  }

  const out = [];
  for (const rec0 of records) {
    const rec = cloneJson(rec0) || {};
    const rowType = String(rec.row_type || "").toUpperCase();

    if (bundleVersion !== null && rec.bundle_version == null) rec.bundle_version = bundleVersion;
    if (bundleType && rec.bundle_type == null) rec.bundle_type = bundleType;
    if (bundleSentAtMs !== null && rec.bundle_sent_at_ms == null) rec.bundle_sent_at_ms = bundleSentAtMs;
    if (rec.t_event_ms == null && bundleSentAtMs !== null) rec.t_event_ms = bundleSentAtMs;

    if (configRec && rowType !== "CONFIG") {
      fillMissing(rec, configRec);
    }

    if (rowType === "EVAL") {
      const parentUid = isNonEmptyString(rec.parent_uid) ? String(rec.parent_uid) : null;
      const parentCanonical = isNonEmptyString(rec.parent_bar_uid_canonical)
        ? String(rec.parent_bar_uid_canonical)
        : null;
      const parentBar = (parentUid ? barsByUid.get(parentUid) : null)
        || (parentCanonical ? barsByCanonical.get(parentCanonical) : null)
        || null;
      if (parentBar) {
        fillMissing(rec, parentBar);
      }
    }

    if (rec.tf_sec == null && isNonEmptyString(rec.tf)) {
      rec.tf_sec = parseTfSec(rec.tf);
    }
    if (rec.stream_id == null) {
      rec.stream_id = inferStreamId(rec);
    }

    const cfg = normalizeCfgSig(rec);
    if (cfg.cfg_sig_raw && isMissing(rec.cfg_sig_raw)) rec.cfg_sig_raw = cfg.cfg_sig_raw;
    if (cfg.cfg_sig_full && isMissing(rec.cfg_sig_full)) rec.cfg_sig_full = cfg.cfg_sig_full;
    if (cfg.cfg_sig_sha256) rec.cfg_sig_sha256 = cfg.cfg_sig_sha256;

    if (isMissing(rec.t_subject_ms)) {
      rec.t_subject_ms = toInt(rec.t_close_ms) ?? toInt(rec.t_eval_close_ms) ?? bundleSentAtMs;
    }
    out.push(rec);
  }

  return out;
}

function sortLogicalRecords(records) {
  const order = { CONFIG: 0, BAR: 1, EVAL: 2 };
  return [...records].sort((a, b) => {
    const ra = order[String(a.row_type || "").toUpperCase()] ?? 99;
    const rb = order[String(b.row_type || "").toUpperCase()] ?? 99;
    return ra - rb;
  });
}

function configKey(runId, cfgSigSha256, cfgSigRaw) {
  return `${runId || "RUN_UNKNOWN"}|${cfgSigSha256 || cfgSigRaw || "CFG_UNKNOWN"}`;
}

async function ensureRawEventsCompatibility() {
  await pool.query(`
    create table if not exists raw_events (
      id bigserial primary key,
      received_at timestamptz not null default now(),
      path text,
      payload jsonb
    );
  `);
  await pool.query(`alter table raw_events add column if not exists request_id text;`);
  await pool.query(`alter table raw_events add column if not exists row_type text;`);
  await pool.query(`create index if not exists raw_events_received_at_idx on raw_events (received_at desc);`);
}

async function ensureMaterializerSchema() {
  await ensureRawEventsCompatibility();

  await pool.query(`
    create table if not exists materializer_state (
      id integer primary key,
      last_raw_event_id bigint not null default 0,
      updated_at timestamptz not null default now()
    );
  `);
  await pool.query(`
    insert into materializer_state (id, last_raw_event_id)
    values (1, 0)
    on conflict (id) do nothing;
  `);

  await pool.query(`
    create table if not exists configs (
      uid text primary key,
      dedup text unique,
      raw_event_id bigint not null,
      request_id text,
      received_at timestamptz not null,
      producer text,
      producer_id text,
      producer_version text,
      stream_id text,
      env text,
      deployment_id text,
      run_id text not null,
      cfg_sig_sha256 text,
      cfg_sig_raw text,
      cfg_sig_full text,
      schema_version integer,
      schema_registry_hash text,
      script_id text,
      script_sha text,
      exchange text,
      symbol text,
      symbol_native text,
      source_family text,
      symbol_role text,
      asset_class text,
      research_cluster text,
      underlying_code text,
      underlying_name text,
      underlying_group text,
      quote_code text,
      instrument_type text,
      tickerid text,
      tf text,
      tf_sec integer,
      seq bigint,
      t_subject_ms bigint,
      t_event_ms bigint,
      emit_reason text,
      enable_eval_horizon boolean,
      exp_id text,
      payload jsonb not null
    );
  `);
  await pool.query(`create index if not exists configs_run_cfg_idx on configs (run_id, cfg_sig_sha256);`);
  await pool.query(`create index if not exists configs_symbol_tf_idx on configs (symbol, tf_sec, received_at desc);`);

  await pool.query(`
    create table if not exists bars (
      uid text primary key,
      dedup text unique,
      raw_event_id bigint not null,
      request_id text,
      received_at timestamptz not null,
      producer text,
      producer_id text,
      producer_version text,
      event_type text,
      stream_id text,
      env text,
      deployment_id text,
      run_id text not null,
      cfg_sig_sha256 text,
      cfg_sig_raw text,
      cfg_sig_full text,
      schema_version integer,
      schema_registry_hash text,
      script_id text,
      script_sha text,
      exchange text,
      symbol text not null,
      symbol_native text,
      source_family text,
      symbol_role text,
      asset_class text,
      research_cluster text,
      underlying_code text,
      underlying_name text,
      underlying_group text,
      quote_code text,
      instrument_type text,
      tickerid text,
      tf text,
      tf_sec integer,
      seq bigint,
      bar_index bigint,
      t_subject_ms bigint,
      t_open_ms bigint,
      t_close_ms bigint,
      t_event_ms bigint,
      t_received_ms bigint,
      time_basis text,
      price_type_used text,
      price_quote text,
      contracts_def text,
      open double precision,
      high double precision,
      low double precision,
      close double precision,
      volume double precision,
      ret1 double precision,
      spot_sym text,
      spot_close double precision,
      premium_sym text,
      premium_idx double precision,
      basis double precision,
      basis_pct double precision,
      premium_pct double precision,
      index_ref_sym text,
      index_ref_close double precision,
      index_basis double precision,
      index_basis_pct double precision,
      oi_close double precision,
      oi_notional double precision,
      oi_source text,
      oi_granularity text,
      funding_rate double precision,
      funding_units text,
      ls_ratio_accounts double precision,
      long_accounts double precision,
      short_accounts double precision,
      liq_buy double precision,
      liq_sell double precision,
      bar_uid_canonical text,
      config_present boolean not null default false,
      config_missing_reason text,
      payload jsonb not null
    );
  `);
  await pool.query(`create index if not exists bars_symbol_tf_close_idx on bars (symbol, tf_sec, t_close_ms desc);`);
  await pool.query(`create index if not exists bars_stream_close_idx on bars (stream_id, t_close_ms desc);`);
  await pool.query(`create index if not exists bars_run_cfg_idx on bars (run_id, cfg_sig_sha256, t_close_ms desc);`);

  await pool.query(`
    create table if not exists evals (
      uid text primary key,
      dedup text unique,
      raw_event_id bigint not null,
      request_id text,
      received_at timestamptz not null,
      producer text,
      producer_id text,
      producer_version text,
      event_type text,
      stream_id text,
      env text,
      deployment_id text,
      run_id text not null,
      cfg_sig_sha256 text,
      cfg_sig_raw text,
      cfg_sig_full text,
      schema_version integer,
      schema_registry_hash text,
      script_id text,
      script_sha text,
      exchange text,
      symbol text,
      symbol_native text,
      source_family text,
      symbol_role text,
      asset_class text,
      research_cluster text,
      underlying_code text,
      underlying_name text,
      underlying_group text,
      quote_code text,
      instrument_type text,
      tickerid text,
      tf text,
      tf_sec integer,
      seq bigint,
      bar_index bigint,
      parent_uid text,
      parent_bar_uid_canonical text,
      t_subject_ms bigint,
      t_eval_close_ms bigint,
      t_event_ms bigint,
      time_basis text,
      W integer,
      windowHigh double precision,
      windowLow double precision,
      barsToHigh integer,
      barsToLow integer,
      close_eval double precision,
      atr14_eval double precision,
      config_present boolean not null default false,
      config_missing_reason text,
      payload jsonb not null
    );
  `);
  await pool.query(`create index if not exists evals_symbol_w_eval_close_idx on evals (symbol, W, t_eval_close_ms desc);`);
  await pool.query(`create index if not exists evals_parent_idx on evals (parent_uid);`);

  console.log("materializer schema OK");
}

function normalizeRecord(rec, row) {
  const cfg = normalizeCfgSig(rec);
  const streamId = inferStreamId(rec);
  return {
    uid: isNonEmptyString(rec.uid) ? String(rec.uid).trim() : null,
    dedup: isNonEmptyString(rec.dedup) ? String(rec.dedup).trim() : (isNonEmptyString(rec.uid) ? String(rec.uid).trim() : null),
    raw_event_id: row.id,
    request_id: row.request_id || null,
    received_at: row.received_at,
    row_type: String(rec.row_type || "").trim().toUpperCase(),
    producer: isNonEmptyString(rec.producer) ? String(rec.producer).trim() : null,
    producer_id: inferProducerId(rec),
    producer_version: isNonEmptyString(rec.producer_version) ? String(rec.producer_version).trim() : null,
    event_type: isNonEmptyString(rec.event_type) ? String(rec.event_type).trim() : null,
    stream_id: streamId,
    env: isNonEmptyString(rec.env) ? String(rec.env).trim() : null,
    deployment_id: isNonEmptyString(rec.deployment_id) ? String(rec.deployment_id).trim() : null,
    run_id: isNonEmptyString(rec.run_id) ? String(rec.run_id).trim() : null,
    cfg_sig_sha256: cfg.cfg_sig_sha256,
    cfg_sig_raw: cfg.cfg_sig_raw,
    cfg_sig_full: cfg.cfg_sig_full,
    schema_version: toInt(rec.schema_version),
    schema_registry_hash: isNonEmptyString(rec.schema_registry_hash) ? String(rec.schema_registry_hash).trim() : null,
    script_id: isNonEmptyString(rec.script_id) ? String(rec.script_id).trim() : null,
    script_sha: isNonEmptyString(rec.script_sha) ? String(rec.script_sha).trim() : null,
    exchange: isNonEmptyString(rec.exchange) ? String(rec.exchange).trim() : null,
    symbol: isNonEmptyString(rec.symbol) ? String(rec.symbol).trim() : null,
    symbol_native: isNonEmptyString(rec.symbol_native) ? String(rec.symbol_native).trim() : null,
    source_family: isNonEmptyString(rec.source_family) ? String(rec.source_family).trim() : null,
    symbol_role: isNonEmptyString(rec.symbol_role) ? String(rec.symbol_role).trim() : null,
    asset_class: isNonEmptyString(rec.asset_class) ? String(rec.asset_class).trim() : null,
    research_cluster: isNonEmptyString(rec.research_cluster) ? String(rec.research_cluster).trim() : null,
    underlying_code: isNonEmptyString(rec.underlying_code) ? String(rec.underlying_code).trim() : null,
    underlying_name: isNonEmptyString(rec.underlying_name) ? String(rec.underlying_name).trim() : null,
    underlying_group: isNonEmptyString(rec.underlying_group) ? String(rec.underlying_group).trim() : null,
    quote_code: isNonEmptyString(rec.quote_code) ? String(rec.quote_code).trim() : null,
    instrument_type: isNonEmptyString(rec.instrument_type) ? String(rec.instrument_type).trim() : null,
    tickerid: isNonEmptyString(rec.tickerid) ? String(rec.tickerid).trim() : null,
    tf: isNonEmptyString(rec.tf) ? String(rec.tf).trim() : null,
    tf_sec: toInt(rec.tf_sec) ?? parseTfSec(rec.tf),
    seq: toInt(rec.seq),
    bar_index: toInt(rec.bar_index),
    t_subject_ms: toInt(rec.t_subject_ms) ?? toInt(rec.t_close_ms),
    t_open_ms: toInt(rec.t_open_ms),
    t_close_ms: toInt(rec.t_close_ms),
    t_event_ms: toInt(rec.t_event_ms),
    t_received_ms: toInt(rec.t_received_ms),
    t_eval_close_ms: toInt(rec.t_eval_close_ms),
    time_basis: isNonEmptyString(rec.time_basis) ? String(rec.time_basis).trim() : null,
    price_type_used: isNonEmptyString(rec.price_type_used) ? String(rec.price_type_used).trim() : null,
    price_quote: isNonEmptyString(rec.price_quote) ? String(rec.price_quote).trim() : null,
    contracts_def: isNonEmptyString(rec.contracts_def) ? String(rec.contracts_def).trim() : null,
    open: toFloat(rec.open),
    high: toFloat(rec.high),
    low: toFloat(rec.low),
    close: toFloat(rec.close),
    volume: toFloat(rec.volume),
    ret1: toFloat(rec.ret1),
    spot_sym: isNonEmptyString(rec.spot_sym) ? String(rec.spot_sym).trim() : null,
    spot_close: toFloat(rec.spot_close),
    premium_sym: isNonEmptyString(rec.premium_sym) ? String(rec.premium_sym).trim() : null,
    premium_idx: toFloat(rec.premium_idx),
    basis: toFloat(rec.basis),
    basis_pct: toFloat(rec.basis_pct),
    premium_pct: toFloat(rec.premium_pct),
    index_ref_sym: isNonEmptyString(rec.index_ref_sym) ? String(rec.index_ref_sym).trim() : null,
    index_ref_close: toFloat(rec.index_ref_close),
    index_basis: toFloat(rec.index_basis),
    index_basis_pct: toFloat(rec.index_basis_pct),
    oi_close: toFloat(rec.oi_close),
    oi_notional: toFloat(rec.oi_notional),
    oi_source: isNonEmptyString(rec.oi_source) ? String(rec.oi_source).trim() : null,
    oi_granularity: isNonEmptyString(rec.oi_granularity) ? String(rec.oi_granularity).trim() : null,
    funding_rate: toFloat(rec.funding_rate),
    funding_units: isNonEmptyString(rec.funding_units) ? String(rec.funding_units).trim() : null,
    ls_ratio_accounts: toFloat(rec.ls_ratio_accounts),
    long_accounts: toFloat(rec.long_accounts),
    short_accounts: toFloat(rec.short_accounts),
    liq_buy: toFloat(rec.liq_buy),
    liq_sell: toFloat(rec.liq_sell),
    bar_uid_canonical: isNonEmptyString(rec.bar_uid_canonical) ? String(rec.bar_uid_canonical).trim() : null,
    parent_uid: isNonEmptyString(rec.parent_uid) ? String(rec.parent_uid).trim() : null,
    parent_bar_uid_canonical: isNonEmptyString(rec.parent_bar_uid_canonical) ? String(rec.parent_bar_uid_canonical).trim() : null,
    W: toInt(rec.W),
    windowHigh: toFloat(rec.windowHigh),
    windowLow: toFloat(rec.windowLow),
    barsToHigh: toInt(rec.barsToHigh),
    barsToLow: toInt(rec.barsToLow),
    close_eval: toFloat(rec.close_eval),
    atr14_eval: toFloat(rec.atr14_eval),
    emit_reason: isNonEmptyString(rec.emit_reason) ? String(rec.emit_reason).trim() : null,
    enable_eval_horizon: rec.enable_eval_horizon === true || rec.enable_eval_horizon === false ? rec.enable_eval_horizon : null,
    exp_id: isNonEmptyString(rec.exp_id) ? String(rec.exp_id).trim() : null,
    payload: cloneJson(rec) || {},
  };
}

async function configExists(client, cache, norm) {
  const key = configKey(norm.run_id, norm.cfg_sig_sha256, norm.cfg_sig_raw);
  if (cache.has(key)) return true;

  let rs;
  if (norm.cfg_sig_sha256) {
    rs = await client.query(
      `select 1 from configs where run_id = $1 and cfg_sig_sha256 = $2 limit 1`,
      [norm.run_id, norm.cfg_sig_sha256]
    );
  } else {
    rs = await client.query(
      `select 1 from configs where run_id = $1 and cfg_sig_raw = $2 limit 1`,
      [norm.run_id, norm.cfg_sig_raw]
    );
  }

  const ok = rs.rowCount > 0;
  if (ok) cache.add(key);
  return ok;
}

async function insertConfig(client, norm, configCache) {
  const key = configKey(norm.run_id, norm.cfg_sig_sha256, norm.cfg_sig_raw);
  await client.query(
    `
      insert into configs (
        uid, dedup, raw_event_id, request_id, received_at,
        producer, producer_id, producer_version, stream_id,
        env, deployment_id, run_id,
        cfg_sig_sha256, cfg_sig_raw, cfg_sig_full,
        schema_version, schema_registry_hash,
        script_id, script_sha,
        exchange, symbol, symbol_native,
        source_family, symbol_role, asset_class, research_cluster,
        underlying_code, underlying_name, underlying_group, quote_code,
        instrument_type, tickerid, tf, tf_sec, seq,
        t_subject_ms, t_event_ms,
        emit_reason, enable_eval_horizon, exp_id,
        payload
      )
      values (
        $1,$2,$3,$4,$5,
        $6,$7,$8,$9,
        $10,$11,$12,
        $13,$14,$15,
        $16,$17,
        $18,$19,
        $20,$21,$22,
        $23,$24,$25,$26,
        $27,$28,$29,$30,
        $31,$32,$33,$34,$35,
        $36,$37,
        $38,$39,$40,
        $41
      )
      on conflict (uid) do update set
        received_at = excluded.received_at,
        request_id = excluded.request_id,
        cfg_sig_sha256 = coalesce(excluded.cfg_sig_sha256, configs.cfg_sig_sha256),
        cfg_sig_raw = coalesce(excluded.cfg_sig_raw, configs.cfg_sig_raw),
        cfg_sig_full = coalesce(excluded.cfg_sig_full, configs.cfg_sig_full),
        payload = excluded.payload
    `,
    [
      norm.uid, norm.dedup, norm.raw_event_id, norm.request_id, norm.received_at,
      norm.producer, norm.producer_id, norm.producer_version, norm.stream_id,
      norm.env, norm.deployment_id, norm.run_id,
      norm.cfg_sig_sha256, norm.cfg_sig_raw, norm.cfg_sig_full,
      norm.schema_version, norm.schema_registry_hash,
      norm.script_id, norm.script_sha,
      norm.exchange, norm.symbol, norm.symbol_native,
      norm.source_family, norm.symbol_role, norm.asset_class, norm.research_cluster,
      norm.underlying_code, norm.underlying_name, norm.underlying_group, norm.quote_code,
      norm.instrument_type, norm.tickerid, norm.tf, norm.tf_sec, norm.seq,
      norm.t_subject_ms, norm.t_event_ms,
      norm.emit_reason, norm.enable_eval_horizon, norm.exp_id,
      norm.payload,
    ]
  );
  configCache.add(key);
}

async function insertBar(client, norm, configCache) {
  const hasConfig = await configExists(client, configCache, norm);
  await client.query(
    `
      insert into bars (
        uid, dedup, raw_event_id, request_id, received_at,
        producer, producer_id, producer_version, event_type, stream_id,
        env, deployment_id, run_id,
        cfg_sig_sha256, cfg_sig_raw, cfg_sig_full,
        schema_version, schema_registry_hash,
        script_id, script_sha,
        exchange, symbol, symbol_native,
        source_family, symbol_role, asset_class, research_cluster,
        underlying_code, underlying_name, underlying_group, quote_code,
        instrument_type, tickerid, tf, tf_sec, seq, bar_index,
        t_subject_ms, t_open_ms, t_close_ms, t_event_ms, t_received_ms, time_basis,
        price_type_used, price_quote, contracts_def,
        open, high, low, close, volume, ret1,
        spot_sym, spot_close, premium_sym, premium_idx,
        basis, basis_pct, premium_pct,
        index_ref_sym, index_ref_close, index_basis, index_basis_pct,
        oi_close, oi_notional, oi_source, oi_granularity,
        funding_rate, funding_units,
        ls_ratio_accounts, long_accounts, short_accounts,
        liq_buy, liq_sell,
        bar_uid_canonical,
        config_present, config_missing_reason,
        payload
      )
      values (
        $1,$2,$3,$4,$5,
        $6,$7,$8,$9,$10,
        $11,$12,$13,
        $14,$15,$16,
        $17,$18,
        $19,$20,
        $21,$22,$23,
        $24,$25,$26,$27,
        $28,$29,$30,$31,
        $32,$33,$34,$35,$36,$37,
        $38,$39,$40,$41,$42,$43,
        $44,$45,$46,
        $47,$48,$49,$50,$51,$52,
        $53,$54,$55,$56,
        $57,$58,$59,
        $60,$61,$62,$63,
        $64,$65,$66,$67,
        $68,$69,
        $70,$71,$72,
        $73,$74,
        $75,
        $76,$77,
        $78
      )
      on conflict (uid) do update set
        request_id = excluded.request_id,
        received_at = excluded.received_at,
        config_present = bars.config_present or excluded.config_present,
        config_missing_reason = case when excluded.config_present then null else coalesce(bars.config_missing_reason, excluded.config_missing_reason) end,
        payload = excluded.payload
    `,
    [
      norm.uid, norm.dedup, norm.raw_event_id, norm.request_id, norm.received_at,
      norm.producer, norm.producer_id, norm.producer_version, norm.event_type, norm.stream_id,
      norm.env, norm.deployment_id, norm.run_id,
      norm.cfg_sig_sha256, norm.cfg_sig_raw, norm.cfg_sig_full,
      norm.schema_version, norm.schema_registry_hash,
      norm.script_id, norm.script_sha,
      norm.exchange, norm.symbol, norm.symbol_native,
      norm.source_family, norm.symbol_role, norm.asset_class, norm.research_cluster,
      norm.underlying_code, norm.underlying_name, norm.underlying_group, norm.quote_code,
      norm.instrument_type, norm.tickerid, norm.tf, norm.tf_sec, norm.seq, norm.bar_index,
      norm.t_subject_ms, norm.t_open_ms, norm.t_close_ms, norm.t_event_ms, norm.t_received_ms, norm.time_basis,
      norm.price_type_used, norm.price_quote, norm.contracts_def,
      norm.open, norm.high, norm.low, norm.close, norm.volume, norm.ret1,
      norm.spot_sym, norm.spot_close, norm.premium_sym, norm.premium_idx,
      norm.basis, norm.basis_pct, norm.premium_pct,
      norm.index_ref_sym, norm.index_ref_close, norm.index_basis, norm.index_basis_pct,
      norm.oi_close, norm.oi_notional, norm.oi_source, norm.oi_granularity,
      norm.funding_rate, norm.funding_units,
      norm.ls_ratio_accounts, norm.long_accounts, norm.short_accounts,
      norm.liq_buy, norm.liq_sell,
      norm.bar_uid_canonical,
      hasConfig,
      hasConfig ? null : "matching_config_not_found",
      norm.payload,
    ]
  );
}

async function insertEval(client, norm, configCache) {
  const hasConfig = await configExists(client, configCache, norm);
  await client.query(
    `
      insert into evals (
        uid, dedup, raw_event_id, request_id, received_at,
        producer, producer_id, producer_version, event_type, stream_id,
        env, deployment_id, run_id,
        cfg_sig_sha256, cfg_sig_raw, cfg_sig_full,
        schema_version, schema_registry_hash,
        script_id, script_sha,
        exchange, symbol, symbol_native,
        source_family, symbol_role, asset_class, research_cluster,
        underlying_code, underlying_name, underlying_group, quote_code,
        instrument_type, tickerid, tf, tf_sec, seq, bar_index,
        parent_uid, parent_bar_uid_canonical,
        t_subject_ms, t_eval_close_ms, t_event_ms, time_basis,
        W, windowHigh, windowLow, barsToHigh, barsToLow,
        close_eval, atr14_eval,
        config_present, config_missing_reason,
        payload
      )
      values (
        $1,$2,$3,$4,$5,
        $6,$7,$8,$9,$10,
        $11,$12,$13,
        $14,$15,$16,
        $17,$18,
        $19,$20,
        $21,$22,$23,
        $24,$25,$26,$27,
        $28,$29,$30,$31,
        $32,$33,$34,$35,$36,$37,
        $38,$39,
        $40,$41,$42,$43,
        $44,$45,$46,$47,$48,
        $49,$50,
        $51,$52,
        $53
      )
      on conflict (uid) do update set
        request_id = excluded.request_id,
        received_at = excluded.received_at,
        config_present = evals.config_present or excluded.config_present,
        config_missing_reason = case when excluded.config_present then null else coalesce(evals.config_missing_reason, excluded.config_missing_reason) end,
        payload = excluded.payload
    `,
    [
      norm.uid, norm.dedup, norm.raw_event_id, norm.request_id, norm.received_at,
      norm.producer, norm.producer_id, norm.producer_version, norm.event_type, norm.stream_id,
      norm.env, norm.deployment_id, norm.run_id,
      norm.cfg_sig_sha256, norm.cfg_sig_raw, norm.cfg_sig_full,
      norm.schema_version, norm.schema_registry_hash,
      norm.script_id, norm.script_sha,
      norm.exchange, norm.symbol, norm.symbol_native,
      norm.source_family, norm.symbol_role, norm.asset_class, norm.research_cluster,
      norm.underlying_code, norm.underlying_name, norm.underlying_group, norm.quote_code,
      norm.instrument_type, norm.tickerid, norm.tf, norm.tf_sec, norm.seq, norm.bar_index,
      norm.parent_uid, norm.parent_bar_uid_canonical,
      norm.t_subject_ms, norm.t_eval_close_ms, norm.t_event_ms, norm.time_basis,
      norm.W, norm.windowHigh, norm.windowLow, norm.barsToHigh, norm.barsToLow,
      norm.close_eval, norm.atr14_eval,
      hasConfig,
      hasConfig ? null : "matching_config_not_found",
      norm.payload,
    ]
  );
}

function extractLogicalRecordsFromRawRow(row) {
  const payload = asObject(row.payload);
  if (!payload) return [];

  // New contract-aligned rows already store one logical record per raw_events row.
  if (String(row.row_type || "").trim()) {
    if (Array.isArray(payload.records)) {
      return sortLogicalRecords(expandLogicalRecords(payload));
    }
    const single = cloneJson(payload) || {};
    if (single.row_type == null) single.row_type = row.row_type;
    if (single.request_id == null && row.request_id != null) single.request_id = row.request_id;
    return sortLogicalRecords(expandLogicalRecords(single));
  }

  // Legacy bundle rows.
  return sortLogicalRecords(expandLogicalRecords(payload));
}

async function materializeBatch(batchSize = 300) {
  const client = await pool.connect();
  let fetched = 0;
  let insertedConfigs = 0;
  let insertedBars = 0;
  let insertedEvals = 0;

  try {
    await client.query("begin");

    const st = await client.query(
      `select last_raw_event_id from materializer_state where id = 1 for update`
    );
    const lastId = BigInt(st.rows[0]?.last_raw_event_id || 0);

    const rs = await client.query(
      `
        select id, received_at, path, request_id, row_type, payload
        from raw_events
        where id > $1
          and (path in ('/tv', '/webhook') or path is null)
        order by id asc
        limit $2
      `,
      [lastId.toString(), batchSize]
    );

    fetched = rs.rows.length;
    let newLast = lastId;
    const configCache = new Set();

    for (const row of rs.rows) {
      const rawEventId = BigInt(row.id);
      if (rawEventId > newLast) newLast = rawEventId;

      const logicalRecords = extractLogicalRecordsFromRawRow(row);
      for (const rec of logicalRecords) {
        const rowType = String(rec.row_type || "").toUpperCase();
        if (!["CONFIG", "BAR", "EVAL"].includes(rowType)) continue;

        const norm = normalizeRecord(rec, row);
        if (!norm.uid || !norm.run_id) continue;

        if (rowType === "CONFIG") {
          const before = await client.query(`select 1 from configs where uid = $1`, [norm.uid]);
          await insertConfig(client, norm, configCache);
          if (before.rowCount === 0) insertedConfigs += 1;
        } else if (rowType === "BAR") {
          const before = await client.query(`select 1 from bars where uid = $1`, [norm.uid]);
          await insertBar(client, norm, configCache);
          if (before.rowCount === 0) insertedBars += 1;
        } else if (rowType === "EVAL") {
          const before = await client.query(`select 1 from evals where uid = $1`, [norm.uid]);
          await insertEval(client, norm, configCache);
          if (before.rowCount === 0) insertedEvals += 1;
        }
      }
    }

    if (fetched > 0) {
      await client.query(
        `
          update materializer_state
          set last_raw_event_id = $1,
              updated_at = now()
          where id = 1
        `,
        [newLast.toString()]
      );
    }

    await client.query("commit");
    return { ok: true, fetched, insertedConfigs, insertedBars, insertedEvals };
  } catch (e) {
    await client.query("rollback").catch(() => {});
    return {
      ok: false,
      error: `${e?.code || ""} ${e?.message || e}`.trim(),
      fetched,
      insertedConfigs,
      insertedBars,
      insertedEvals,
    };
  } finally {
    client.release();
  }
}

async function shutdown(signal) {
  try {
    console.log(`materializer shutting down (${signal})...`);
    await pool.end();
  } catch {
    // ignore
  } finally {
    process.exit(0);
  }
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));

async function main() {
  const batchSize = Math.max(
    1,
    Math.min(parseInt(process.env.MATERIALIZER_BATCH_SIZE || "300", 10) || 300, 5000)
  );
  const idleSleepMs = Math.max(
    250,
    parseInt(process.env.MATERIALIZER_IDLE_SLEEP_MS || "5000", 10) || 5000
  );
  const errorSleepMs = Math.max(
    250,
    parseInt(process.env.MATERIALIZER_ERROR_SLEEP_MS || "5000", 10) || 5000
  );

  await ensureMaterializerSchema();

  console.log(
    `materializer starting: batchSize=${batchSize} idleSleepMs=${idleSleepMs} errorSleepMs=${errorSleepMs}`
  );

  while (true) {
    const r = await materializeBatch(batchSize);

    if (!r.ok) {
      console.error("materializer error:", r.error);
      await sleep(errorSleepMs);
      continue;
    }

    if (r.fetched === 0) {
      await sleep(idleSleepMs);
      continue;
    }

    console.log(
      `materialized: fetched_raw=${r.fetched} inserted_configs=${r.insertedConfigs} inserted_bars=${r.insertedBars} inserted_evals=${r.insertedEvals}`
    );
  }
}

main().catch((e) => {
  console.error("FATAL:", e);
  process.exit(1);
});
