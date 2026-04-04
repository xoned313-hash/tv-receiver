import express from "express";
import pg from "pg";
import crypto from "crypto";

const { Pool } = pg;
const app = express();

app.use(express.text({ type: "*/*", limit: "2mb" }));

const PORT = parseInt(process.env.PORT || "8080", 10);
const RECEIVER_ENV = (process.env.RECEIVER_ENV || "prod").trim().toLowerCase();
const DATABASE_URL_RAW = (process.env.DATABASE_URL || "").trim();
const CA_CERT = (process.env.CA_CERT || process.env.DATABASE_CA_CERT || "").trim();
const PGSSL_INSECURE = (process.env.PGSSL_INSECURE || "").trim() === "1";
const TV_ALLOWED_IPS = (process.env.TV_ALLOWED_IPS || "").trim();
const ALLOW_UNTRUSTED_INGRESS = (process.env.ALLOW_UNTRUSTED_INGRESS || "").trim() === "1";

if (!DATABASE_URL_RAW) {
  console.error("FATAL: DATABASE_URL is not set");
  process.exit(1);
}
if (!CA_CERT && !PGSSL_INSECURE) {
  console.error("FATAL: DATABASE_CA_CERT (or CA_CERT) is required unless PGSSL_INSECURE=1 for DEV only");
  process.exit(1);
}
if (PGSSL_INSECURE && RECEIVER_ENV === "prod") {
  console.error("FATAL: PGSSL_INSECURE=1 is forbidden when RECEIVER_ENV=prod");
  process.exit(1);
}
if (ALLOW_UNTRUSTED_INGRESS && RECEIVER_ENV === "prod") {
  console.error("FATAL: ALLOW_UNTRUSTED_INGRESS=1 is forbidden when RECEIVER_ENV=prod");
  process.exit(1);
}
if (RECEIVER_ENV === "prod" && !TV_ALLOWED_IPS) {
  console.error("FATAL: TV_ALLOWED_IPS must be set in prod");
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

const SUPPORTED_ROW_TYPES = new Set(["CONFIG", "BAR", "EVAL", "ERROR", "INGRESS_REJECT", "DUPLICATE"]);
const REDACT_KEYS = new Set([
  "secret",
  "webhook_secret",
  "webhooksecret",
  "token",
  "authorization",
  "api_key",
  "apikey",
  "password",
]);

const CORE_ALLOWED_FIELDS = new Set([
  "row_type", "schema_version", "log_tag", "producer", "producer_version", "event_type",
  "json_schema_version", "wide_schema_version", "csv_schema_version",
  "env", "deployment_id", "timezone_id", "timezone", "schema_registry_version", "schema_registry_hash",
  "script_id", "script_sha", "stream_id", "universe_id", "alert_tag",
  "run_id", "cfg_sig", "cfg_sig_raw", "cfg_sig_full", "cfg_sig_sha256",
  "uid", "dedup", "bar_uid_canonical", "parent_uid", "parent_bar_uid_canonical",
  "seq", "exchange", "symbol", "symbol_native", "instrument_type", "tickerid",
  "tf", "tf_sec", "bar_index",
  "source_family", "symbol_role", "asset_class", "research_cluster",
  "underlying_code", "underlying_name", "underlying_group", "quote_code",
  "t_subject_ms", "t_open_ms", "t_close_ms", "t_event_ms", "t_eval_close_ms", "t_tradingday_ms",
  "producer_latency_ms", "time_basis", "exchange_timezone",
  "bar_open_offset_sec_utc", "bar_close_offset_sec_utc",
  "base_tickerid", "is_perp", "is_continuous_future", "continuous_contract_rank", "continuous_roll_note",
  "symbol_namespaced", "price_quote", "contracts_def", "price_type_used", "price_type_reason",
  "open", "high", "low", "close", "volume", "ret1",
  "spot_sym", "spot_has", "spot_close",
  "premium_sym", "premium_has", "premium_idx", "basis", "basis_pct", "premium_pct",
  "index_ref_sym", "index_ref_has", "index_ref_close", "index_basis", "index_basis_pct",
  "enable_derivs_req", "req_primary", "req_fallback", "req_gaps", "req_repaint",
  "oi_expected", "oi_reason", "oi_source", "oi_granularity", "oi_close", "oi_has", "oi_used_fallback", "oi_notional",
  "funding_expected", "funding_reason", "funding_units", "funding_rate", "funding_has", "funding_used_fallback", "funding_sym_used",
  "ls_expected", "ls_reason", "ls_ratio_accounts", "ls_units", "ls_has", "ls_used_fallback",
  "long_accounts", "long_accounts_units", "long_has", "long_used_fallback",
  "short_accounts", "short_accounts_units", "short_has", "short_used_fallback",
  "liq_expected", "liq_reason", "liq_buy", "liq_buy_has", "liq_buy_used_fallback",
  "liq_sell", "liq_sell_has", "liq_sell_used_fallback", "liq_has",
  "emit_reason", "emit_mode", "mode_json", "mode_csv", "enable_logging", "include_csv_in_json",
  "emit_config_on_change", "config_beacon_every_bars", "emit_csv_header_line",
  "enable_eval_horizon", "eval_w1", "eval_w2", "eval_w3", "max_pending_evals",
  "use_log_date_filter", "log_start_date_ms", "exp_id", "exp_note", "in_log_window",
  "sep", "spot_override", "premium_override", "enable_index_reference", "index_override",
  "namespace_non_perp_symbols", "use_chart_sym_req", "sym_primary_req", "sym_fallback_req",
  "oi_fail_hard", "csv_col_count", "csv_header", "csv",
  "research_profile", "ap_single_timeframe_only", "ap_mtf_removed", "include_parity_st_macd",
  "wt_profile", "parity_profile", "ml_profile", "pivot_simple_profile", "pivot_standard_profile", "compression_note",
  "W", "windowHigh", "windowLow", "barsToHigh", "barsToLow", "close_eval", "atr14_eval",
  "bundle_version", "bundle_type", "bundle_sent_at_ms", "sent_at_ms",
  "request_id", "ip_hash", "user_agent_hash", "path", "notes"
]);

const ALLOWED_PREFIXES = [
  "ps_", "pstd_", "wt_", "ml_", "kernel_", "st_", "macd_", "lr_", "liq_", "oi_", "funding_", "ls_"
];

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

function parseAllowedIps(raw) {
  const set = new Set();
  for (const part of String(raw || "").split(",")) {
    const ip = normalizeClientIp(part.trim());
    if (ip) set.add(ip);
  }
  return set;
}

const ALLOWED_IP_SET = parseAllowedIps(TV_ALLOWED_IPS);
if (RECEIVER_ENV === "prod" && ALLOWED_IP_SET.has("*")) {
  console.error("FATAL: TV_ALLOWED_IPS=* is forbidden when RECEIVER_ENV=prod");
  process.exit(1);
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

function parseJsonBody(raw) {
  const s = typeof raw === "string" ? raw.trim() : "";
  if (!s) return { ok: false, error: "empty_body", raw_preview: "" };
  try {
    return { ok: true, value: JSON.parse(s) };
  } catch {
    return { ok: false, error: "json_parse_failed", raw_preview: s.slice(0, 5000) };
  }
}

function redactDeep(value) {
  if (value === null || value === undefined) return value;
  if (Array.isArray(value)) return value.map((v) => redactDeep(v));
  if (typeof value !== "object") return value;

  const out = {};
  for (const [k, v] of Object.entries(value)) {
    const key = String(k).toLowerCase();
    if (REDACT_KEYS.has(key)) {
      out[k] = "[REDACTED]";
    } else {
      out[k] = redactDeep(v);
    }
  }
  return out;
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

function isoFromMs(ms) {
  try {
    return new Date(ms).toISOString();
  } catch {
    return null;
  }
}

function formatDayIdUTC(ms) {
  return isoFromMs(ms)?.slice(0, 10) || "1970-01-01";
}

function formatDayIdLocal(ms, timeZone) {
  try {
    const fmt = new Intl.DateTimeFormat("en-CA", {
      timeZone,
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
    });
    return fmt.format(new Date(ms));
  } catch {
    return formatDayIdUTC(ms);
  }
}

function sessionIdFromUTC(ms) {
  return "UTC_DAY_" + formatDayIdUTC(ms);
}

function normalizeClientIp(raw) {
  const s = String(raw || "").trim();
  if (!s) return "";
  const first = s.split(",")[0].trim();
  return first.startsWith("::ffff:") ? first.slice(7) : first;
}

function getClientIp(req) {
  const xf = (req.headers["x-forwarded-for"] || "").toString();
  if (xf) return normalizeClientIp(xf);
  return normalizeClientIp(req.socket?.remoteAddress || "");
}

function getUserAgent(req) {
  return (req.headers["user-agent"] || "").toString();
}

function isTrustedSource(ip) {
  if (ALLOW_UNTRUSTED_INGRESS) return true;
  if (ALLOWED_IP_SET.has("*")) return true;
  if (!ip) return false;
  return ALLOWED_IP_SET.has(normalizeClientIp(ip));
}

function makeRequestId() {
  return crypto.randomUUID ? crypto.randomUUID() : sha256Hex(`${Date.now()}|${Math.random()}`);
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

function envFrom(rec) {
  const e = String(rec.env || "").trim().toLowerCase();
  if (e === "prod" || e === "staging" || e === "dev") return e;
  if (RECEIVER_ENV === "staging") return "staging";
  if (RECEIVER_ENV === "dev") return "dev";
  return "prod";
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
      // keep original string
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
    return { cfg_sig_raw: raw.toLowerCase(), cfg_sig_full: null, cfg_sig_sha256: raw.toLowerCase() };
  }

  if (isNonEmptyString(raw)) {
    return { cfg_sig_raw: raw, cfg_sig_full: null, cfg_sig_sha256: sha256Hex(raw) };
  }

  return { cfg_sig_raw: null, cfg_sig_full: null, cfg_sig_sha256: null };
}

function fillMissing(target, source, keys = CONTEXT_KEYS) {
  if (!source) return target;
  for (const key of keys) {
    if (isMissing(target[key]) && !isMissing(source[key])) {
      target[key] = source[key];
    }
  }
  return target;
}

function cloneJson(value) {
  return value == null ? value : JSON.parse(JSON.stringify(value));
}

function requiredKeysForRowType(rowType) {
  const common = [
    "row_type", "uid", "run_id", "cfg_sig",
    "schema_version", "env", "deployment_id",
    "exchange", "symbol", "tickerid", "instrument_type", "tf", "tf_sec",
    "seq", "t_subject_ms", "t_event_ms"
  ];
  if (rowType === "EVAL") return common.concat(["parent_uid"]);
  return common;
}

function isKnownField(key) {
  if (CORE_ALLOWED_FIELDS.has(key)) return true;
  return ALLOWED_PREFIXES.some((prefix) => key.startsWith(prefix));
}

function unknownKeysCount(rec) {
  return Object.keys(rec || {}).filter((key) => !isKnownField(key)).length;
}

function minimumRequiredMissingCount(rec, rowType) {
  let missing = 0;
  for (const key of requiredKeysForRowType(rowType)) {
    if (isMissing(rec[key])) missing += 1;
  }
  return missing;
}

function buildFailureRecord({
  row_type,
  reason,
  request_id,
  path,
  ip_hash,
  user_agent_hash,
  t_received_ms,
  auth_ok,
  parse_ok,
  raw_payload,
  record_index = 0,
  raw_request_id = null,
}) {
  const payload = redactDeep({
    reason,
    request_id,
    path,
    raw_payload,
  });
  const payloadString = stableStringify(payload);
  const uid = `${row_type}|${request_id || t_received_ms}|${record_index}`;
  return {
    raw_request_id,
    record_index,
    uid,
    row_type,
    parent_uid: null,
    run_id: "RUN_UNKNOWN",
    cfg_sig: "CFG_UNKNOWN",
    cfg_sig_raw: "CFG_UNKNOWN",
    cfg_sig_full: null,
    cfg_sig_sha256: sha256Hex("CFG_UNKNOWN"),
    schema_version: 0,
    schema_registry_hash: "0".repeat(64),
    producer: "INGRESS",
    producer_id: "INGRESS",
    producer_version: "1.0.0",
    event_type: row_type,
    stream_id: "INGRESS",
    env: envFrom({ env: RECEIVER_ENV }),
    deployment_id: "INGRESS",
    exchange: "UNKNOWN",
    symbol: "UNKNOWN",
    symbol_native: null,
    source_family: null,
    symbol_role: null,
    asset_class: null,
    research_cluster: null,
    underlying_code: null,
    underlying_name: null,
    underlying_group: null,
    quote_code: null,
    tickerid: "UNKNOWN",
    instrument_type: "UNKNOWN",
    tf: "UNKNOWN",
    tf_sec: 0,
    seq: 0,
    bundle_version: null,
    bundle_type: null,
    bundle_sent_at_ms: null,
    t_subject_ms: t_received_ms,
    t_event_ms: t_received_ms,
    t_received_ms,
    latency_ms: 0,
    t_subject_iso: isoFromMs(t_received_ms),
    t_event_iso: isoFromMs(t_received_ms),
    timezone: "UTC",
    day_id_utc: formatDayIdUTC(t_received_ms),
    day_id_local: formatDayIdUTC(t_received_ms),
    session_id: sessionIdFromUTC(t_received_ms),
    auth_ok: Boolean(auth_ok),
    parse_ok: Boolean(parse_ok),
    schema_match_ok: false,
    unknown_keys_count: 0,
    missing_required_count: 0,
    payload_sha256: sha256Hex(payloadString),
    payload_size_bytes: Buffer.byteLength(payloadString, "utf8"),
    ip_hash,
    user_agent_hash,
    request_id,
    path,
    script_sha: null,
    notes: reason,
    payload,
  };
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

function prepareLogicalRecord(rec, meta) {
  const rowTypeRaw = String(rec.row_type || "").trim().toUpperCase();
  if (!rowTypeRaw) {
    return buildFailureRecord({
      row_type: "ERROR",
      reason: "missing_row_type",
      request_id: meta.request_id,
      path: meta.path,
      ip_hash: meta.ip_hash,
      user_agent_hash: meta.user_agent_hash,
      t_received_ms: meta.t_received_ms,
      auth_ok: meta.auth_ok,
      parse_ok: true,
      raw_payload: rec,
      record_index: meta.record_index,
      raw_request_id: meta.raw_request_id,
    });
  }

  const cfg = normalizeCfgSig(rec);
  const uid = isNonEmptyString(rec.uid) ? String(rec.uid).trim() : `${rowTypeRaw}|${meta.request_id}|${meta.record_index}`;
  const tfSec = toInt(rec.tf_sec) ?? parseTfSec(rec.tf) ?? 0;
  const tSubjectMs = toInt(rec.t_subject_ms)
    ?? toInt(rec.t_close_ms)
    ?? toInt(rec.t_eval_close_ms)
    ?? toInt(rec.bundle_sent_at_ms)
    ?? meta.t_received_ms;
  const tEventMs = toInt(rec.t_event_ms)
    ?? toInt(rec.bundle_sent_at_ms)
    ?? meta.t_received_ms;
  const timezone = isNonEmptyString(rec.timezone_id)
    ? String(rec.timezone_id).trim()
    : isNonEmptyString(rec.timezone)
      ? String(rec.timezone).trim()
      : "UTC";

  const producerId = inferProducerId(rec);
  const streamId = inferStreamId(rec);
  const env = envFrom(rec);

  const payload = redactDeep({
    ...rec,
    producer_id: producerId,
    stream_id: streamId,
    cfg_sig_raw: cfg.cfg_sig_raw,
    cfg_sig_full: cfg.cfg_sig_full,
    cfg_sig_sha256: cfg.cfg_sig_sha256,
  });
  const payloadString = stableStringify(payload);

  const working = {
    row_type: rowTypeRaw,
    uid,
    run_id: isNonEmptyString(rec.run_id) ? String(rec.run_id).trim() : "RUN_UNKNOWN",
    cfg_sig: cfg.cfg_sig_sha256 || cfg.cfg_sig_raw || "CFG_UNKNOWN",
    schema_version: toInt(rec.schema_version) ?? 0,
    env,
    deployment_id: isNonEmptyString(rec.deployment_id) ? String(rec.deployment_id).trim() : "UNKNOWN",
    exchange: isNonEmptyString(rec.exchange) ? String(rec.exchange).trim() : "UNKNOWN",
    symbol: isNonEmptyString(rec.symbol) ? String(rec.symbol).trim() : "UNKNOWN",
    tickerid: isNonEmptyString(rec.tickerid) ? String(rec.tickerid).trim() : "UNKNOWN",
    instrument_type: isNonEmptyString(rec.instrument_type) ? String(rec.instrument_type).trim() : "UNKNOWN",
    tf: isNonEmptyString(rec.tf) ? String(rec.tf).trim() : "UNKNOWN",
    tf_sec: tfSec,
    seq: toInt(rec.seq) ?? 0,
    t_subject_ms: tSubjectMs,
    t_event_ms: tEventMs,
    parent_uid: isNonEmptyString(rec.parent_uid) ? String(rec.parent_uid).trim() : null,
  };

  const missingRequired = minimumRequiredMissingCount(working, rowTypeRaw);
  const unknownCount = unknownKeysCount(payload);

  return {
    raw_request_id: meta.raw_request_id,
    record_index: meta.record_index,
    uid,
    row_type: rowTypeRaw,
    parent_uid: working.parent_uid,
    run_id: working.run_id,
    cfg_sig: working.cfg_sig,
    cfg_sig_raw: cfg.cfg_sig_raw,
    cfg_sig_full: cfg.cfg_sig_full,
    cfg_sig_sha256: cfg.cfg_sig_sha256,
    schema_version: working.schema_version,
    schema_registry_hash: isNonEmptyString(rec.schema_registry_hash)
      ? String(rec.schema_registry_hash).trim()
      : "0".repeat(64),
    producer: isNonEmptyString(rec.producer) ? String(rec.producer).trim() : "INGRESS",
    producer_id: producerId,
    producer_version: isNonEmptyString(rec.producer_version) ? String(rec.producer_version).trim() : null,
    event_type: isNonEmptyString(rec.event_type) ? String(rec.event_type).trim() : rowTypeRaw,
    stream_id: streamId,
    env,
    deployment_id: working.deployment_id,
    exchange: working.exchange,
    symbol: working.symbol,
    symbol_native: isNonEmptyString(rec.symbol_native) ? String(rec.symbol_native).trim() : null,
    source_family: isNonEmptyString(rec.source_family) ? String(rec.source_family).trim() : null,
    symbol_role: isNonEmptyString(rec.symbol_role) ? String(rec.symbol_role).trim() : null,
    asset_class: isNonEmptyString(rec.asset_class) ? String(rec.asset_class).trim() : null,
    research_cluster: isNonEmptyString(rec.research_cluster) ? String(rec.research_cluster).trim() : null,
    underlying_code: isNonEmptyString(rec.underlying_code) ? String(rec.underlying_code).trim() : null,
    underlying_name: isNonEmptyString(rec.underlying_name) ? String(rec.underlying_name).trim() : null,
    underlying_group: isNonEmptyString(rec.underlying_group) ? String(rec.underlying_group).trim() : null,
    quote_code: isNonEmptyString(rec.quote_code) ? String(rec.quote_code).trim() : null,
    tickerid: working.tickerid,
    instrument_type: working.instrument_type,
    tf: working.tf,
    tf_sec: working.tf_sec,
    seq: working.seq,
    bundle_version: toInt(rec.bundle_version),
    bundle_type: isNonEmptyString(rec.bundle_type) ? String(rec.bundle_type).trim() : null,
    bundle_sent_at_ms: toInt(rec.bundle_sent_at_ms) ?? toInt(rec.sent_at_ms),
    t_subject_ms: working.t_subject_ms,
    t_event_ms: working.t_event_ms,
    t_received_ms: meta.t_received_ms,
    latency_ms: meta.t_received_ms - working.t_event_ms,
    t_subject_iso: isoFromMs(working.t_subject_ms),
    t_event_iso: isoFromMs(working.t_event_ms),
    timezone,
    day_id_utc: formatDayIdUTC(working.t_subject_ms),
    day_id_local: formatDayIdLocal(working.t_subject_ms, timezone),
    session_id: sessionIdFromUTC(working.t_subject_ms),
    auth_ok: Boolean(meta.auth_ok),
    parse_ok: true,
    schema_match_ok: missingRequired === 0 && SUPPORTED_ROW_TYPES.has(rowTypeRaw),
    unknown_keys_count: unknownCount,
    missing_required_count: missingRequired,
    request_id: meta.request_id,
    ip_hash: meta.ip_hash,
    user_agent_hash: meta.user_agent_hash,
    path: meta.path,
    script_sha: isNonEmptyString(rec.script_sha) ? String(rec.script_sha).trim() : null,
    notes: null,
    payload_sha256: sha256Hex(payloadString),
    payload_size_bytes: Buffer.byteLength(payloadString, "utf8"),
    payload,
  };
}

async function ensureSchema() {
  await pool.query(`
    create table if not exists runs (
      run_id text primary key,
      env text not null,
      deployment_id text not null,
      producer_id text not null,
      timezone text not null default 'UTC',
      started_at_ms bigint not null,
      started_at_iso text not null,
      first_cfg_sig_raw text,
      first_cfg_sig_sha256 text,
      last_cfg_sig_raw text,
      last_cfg_sig_sha256 text,
      created_at_ms bigint not null,
      updated_at timestamptz not null default now()
    );
  `);

  await pool.query(`
    create table if not exists raw_requests (
      id bigserial primary key,
      request_id text not null unique,
      received_at timestamptz not null default now(),
      path text,
      method text,
      content_type text,
      source_ip_hash text,
      user_agent_hash text,
      auth_ok boolean not null default false,
      parse_ok boolean not null default false,
      payload_sha256 text,
      payload_size_bytes integer,
      bundle_version integer,
      bundle_type text,
      sent_at_ms bigint,
      record_count integer not null default 0,
      raw_body text,
      raw_body_redacted text,
      notes text
    );
  `);

  await pool.query(`
    create table if not exists raw_events (
      id bigserial primary key,
      received_at timestamptz not null default now(),
      path text,
      payload jsonb
    );
  `);

  const addColumns = [
    ["raw_request_id", "bigint"],
    ["request_id", "text"],
    ["record_index", "integer"],
    ["row_type", "text"],
    ["uid", "text"],
    ["parent_uid", "text"],
    ["run_id", "text"],
    ["cfg_sig", "text"],
    ["cfg_sig_raw", "text"],
    ["cfg_sig_full", "text"],
    ["cfg_sig_sha256", "text"],
    ["schema_version", "integer"],
    ["schema_registry_hash", "text"],
    ["producer", "text"],
    ["producer_id", "text"],
    ["producer_version", "text"],
    ["event_type", "text"],
    ["stream_id", "text"],
    ["env", "text"],
    ["deployment_id", "text"],
    ["exchange", "text"],
    ["symbol", "text"],
    ["symbol_native", "text"],
    ["source_family", "text"],
    ["symbol_role", "text"],
    ["asset_class", "text"],
    ["research_cluster", "text"],
    ["underlying_code", "text"],
    ["underlying_name", "text"],
    ["underlying_group", "text"],
    ["quote_code", "text"],
    ["tickerid", "text"],
    ["instrument_type", "text"],
    ["tf", "text"],
    ["tf_sec", "integer"],
    ["seq", "bigint"],
    ["bundle_version", "integer"],
    ["bundle_type", "text"],
    ["bundle_sent_at_ms", "bigint"],
    ["t_subject_ms", "bigint"],
    ["t_event_ms", "bigint"],
    ["t_received_ms", "bigint"],
    ["latency_ms", "bigint"],
    ["t_subject_iso", "text"],
    ["t_event_iso", "text"],
    ["timezone", "text"],
    ["day_id_utc", "text"],
    ["day_id_local", "text"],
    ["session_id", "text"],
    ["auth_ok", "boolean"],
    ["parse_ok", "boolean"],
    ["schema_match_ok", "boolean"],
    ["unknown_keys_count", "integer"],
    ["missing_required_count", "integer"],
    ["payload_sha256", "text"],
    ["payload_size_bytes", "integer"],
    ["ip_hash", "text"],
    ["user_agent_hash", "text"],
    ["script_sha", "text"],
    ["notes", "text"],
    ["payload_raw_redacted", "jsonb"],
  ];

  for (const [col, type] of addColumns) {
    await pool.query(`alter table raw_events add column if not exists ${col} ${type};`);
  }

  await pool.query(`create index if not exists raw_requests_received_idx on raw_requests (received_at desc);`);
  await pool.query(`create index if not exists raw_requests_payload_hash_idx on raw_requests (payload_sha256);`);
  await pool.query(`create index if not exists raw_events_received_at_idx on raw_events (received_at desc);`);
  await pool.query(`create unique index if not exists raw_events_uid_uidx on raw_events (uid) where uid is not null;`);
  await pool.query(`
    create unique index if not exists raw_events_run_seq_uidx
    on raw_events (run_id, seq)
    where run_id is not null and seq is not null and row_type in ('CONFIG', 'BAR', 'EVAL');
  `);
  await pool.query(`create index if not exists raw_events_raw_request_idx on raw_events (raw_request_id);`);
  await pool.query(`create index if not exists raw_events_row_type_received_idx on raw_events (row_type, received_at desc);`);
  await pool.query(`create index if not exists raw_events_symbol_tf_subject_idx on raw_events (symbol, tf_sec, t_subject_ms desc);`);
  await pool.query(`create index if not exists runs_started_idx on runs (started_at_ms desc);`);
}

async function upsertRun(client, row) {
  await client.query(
    `
      insert into runs (
        run_id, env, deployment_id, producer_id, timezone,
        started_at_ms, started_at_iso,
        first_cfg_sig_raw, first_cfg_sig_sha256,
        last_cfg_sig_raw, last_cfg_sig_sha256,
        created_at_ms, updated_at
      )
      values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$8,$9,$10,now())
      on conflict (run_id) do update set
        env = excluded.env,
        deployment_id = excluded.deployment_id,
        producer_id = excluded.producer_id,
        timezone = excluded.timezone,
        started_at_ms = least(runs.started_at_ms, excluded.started_at_ms),
        started_at_iso = case
          when runs.started_at_ms <= excluded.started_at_ms then runs.started_at_iso
          else excluded.started_at_iso
        end,
        last_cfg_sig_raw = coalesce(excluded.last_cfg_sig_raw, runs.last_cfg_sig_raw),
        last_cfg_sig_sha256 = coalesce(excluded.last_cfg_sig_sha256, runs.last_cfg_sig_sha256),
        updated_at = now()
    `,
    [
      row.run_id,
      row.env,
      row.deployment_id,
      row.producer_id,
      row.timezone || "UTC",
      row.t_subject_ms || row.t_received_ms,
      row.t_subject_iso || isoFromMs(row.t_subject_ms || row.t_received_ms),
      row.cfg_sig_raw,
      row.cfg_sig_sha256,
      row.t_received_ms || Date.now(),
    ]
  );
}

async function insertRawRequest(client, row) {
  const rs = await client.query(
    `
      insert into raw_requests (
        request_id, path, method, content_type,
        source_ip_hash, user_agent_hash,
        auth_ok, parse_ok,
        payload_sha256, payload_size_bytes,
        bundle_version, bundle_type, sent_at_ms, record_count,
        raw_body, raw_body_redacted, notes
      )
      values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
      on conflict (request_id) do update set
        auth_ok = excluded.auth_ok,
        parse_ok = excluded.parse_ok,
        payload_sha256 = excluded.payload_sha256,
        payload_size_bytes = excluded.payload_size_bytes,
        bundle_version = excluded.bundle_version,
        bundle_type = excluded.bundle_type,
        sent_at_ms = excluded.sent_at_ms,
        record_count = excluded.record_count,
        raw_body = excluded.raw_body,
        raw_body_redacted = excluded.raw_body_redacted,
        notes = excluded.notes
      returning id
    `,
    [
      row.request_id,
      row.path,
      row.method,
      row.content_type,
      row.source_ip_hash,
      row.user_agent_hash,
      row.auth_ok,
      row.parse_ok,
      row.payload_sha256,
      row.payload_size_bytes,
      row.bundle_version,
      row.bundle_type,
      row.sent_at_ms,
      row.record_count,
      row.raw_body,
      row.raw_body_redacted,
      row.notes,
    ]
  );
  return rs.rows[0].id;
}

async function insertRawEvent(client, row) {
  await client.query(
    `
      insert into raw_events (
        raw_request_id, path, payload, request_id, record_index,
        row_type, uid, parent_uid,
        run_id, cfg_sig, cfg_sig_raw, cfg_sig_full, cfg_sig_sha256,
        schema_version, schema_registry_hash,
        producer, producer_id, producer_version, event_type, stream_id,
        env, deployment_id,
        exchange, symbol, symbol_native, source_family, symbol_role, asset_class, research_cluster,
        underlying_code, underlying_name, underlying_group, quote_code,
        tickerid, instrument_type, tf, tf_sec, seq,
        bundle_version, bundle_type, bundle_sent_at_ms,
        t_subject_ms, t_event_ms, t_received_ms, latency_ms,
        t_subject_iso, t_event_iso, timezone, day_id_utc, day_id_local, session_id,
        auth_ok, parse_ok, schema_match_ok, unknown_keys_count, missing_required_count,
        payload_sha256, payload_size_bytes, ip_hash, user_agent_hash, script_sha, notes,
        payload_raw_redacted
      )
      values (
        $1,$2,$3,$4,$5,
        $6,$7,$8,
        $9,$10,$11,$12,$13,
        $14,$15,
        $16,$17,$18,$19,$20,
        $21,$22,
        $23,$24,$25,$26,$27,$28,$29,
        $30,$31,$32,$33,
        $34,$35,$36,$37,$38,
        $39,$40,$41,
        $42,$43,$44,$45,
        $46,$47,$48,$49,$50,$51,
        $52,$53,$54,$55,$56,
        $57,$58,$59,$60,$61,$62,
        $63
      )
      on conflict do nothing
    `,
    [
      row.raw_request_id,
      row.path,
      row.payload,
      row.request_id,
      row.record_index,
      row.row_type,
      row.uid,
      row.parent_uid,
      row.run_id,
      row.cfg_sig,
      row.cfg_sig_raw,
      row.cfg_sig_full,
      row.cfg_sig_sha256,
      row.schema_version,
      row.schema_registry_hash,
      row.producer,
      row.producer_id,
      row.producer_version,
      row.event_type,
      row.stream_id,
      row.env,
      row.deployment_id,
      row.exchange,
      row.symbol,
      row.symbol_native,
      row.source_family,
      row.symbol_role,
      row.asset_class,
      row.research_cluster,
      row.underlying_code,
      row.underlying_name,
      row.underlying_group,
      row.quote_code,
      row.tickerid,
      row.instrument_type,
      row.tf,
      row.tf_sec,
      row.seq,
      row.bundle_version,
      row.bundle_type,
      row.bundle_sent_at_ms,
      row.t_subject_ms,
      row.t_event_ms,
      row.t_received_ms,
      row.latency_ms,
      row.t_subject_iso,
      row.t_event_iso,
      row.timezone,
      row.day_id_utc,
      row.day_id_local,
      row.session_id,
      row.auth_ok,
      row.parse_ok,
      row.schema_match_ok,
      row.unknown_keys_count,
      row.missing_required_count,
      row.payload_sha256,
      row.payload_size_bytes,
      row.ip_hash,
      row.user_agent_hash,
      row.script_sha,
      row.notes,
      row.payload,
    ]
  );
}

function requestEnvelopeFromBody(body) {
  const asObj = asObject(body);
  if (!asObj) {
    return { bundle_version: null, bundle_type: null, sent_at_ms: null, record_count: 0 };
  }
  if (Array.isArray(asObj.records)) {
    return {
      bundle_version: toInt(asObj.bundle_version),
      bundle_type: isNonEmptyString(asObj.bundle_type) ? String(asObj.bundle_type).trim() : null,
      sent_at_ms: toInt(asObj.sent_at_ms),
      record_count: asObj.records.length,
    };
  }
  return {
    bundle_version: toInt(asObj.bundle_version),
    bundle_type: isNonEmptyString(asObj.bundle_type) ? String(asObj.bundle_type).trim() : null,
    sent_at_ms: toInt(asObj.sent_at_ms),
    record_count: 1,
  };
}

async function persistFailure(client, failure) {
  await upsertRun(client, failure);
  await insertRawEvent(client, failure);
}

async function ingestRequest(req, res) {
  const requestId = makeRequestId();
  const tReceivedMs = Date.now();
  const path = req.path;
  const method = req.method;
  const clientIp = getClientIp(req);
  const ipHash = sha256Hex(clientIp || "");
  const userAgentHash = sha256Hex(getUserAgent(req) || "");
  const authOk = isTrustedSource(clientIp);
  const rawBody = typeof req.body === "string" ? req.body : "";
  const contentType = (req.headers["content-type"] || "").toString();
  const parsed = parseJsonBody(rawBody);
  const originalUrl = (req.originalUrl || "").toString();
  const queryString = originalUrl.includes("?") ? originalUrl.slice(originalUrl.indexOf("?") + 1) : "";

  const parsedBody = parsed.ok ? parsed.value : null;
  const envelope = requestEnvelopeFromBody(parsedBody);
  const rawBodyRedacted = parsed.ok ? stableStringify(redactDeep(parsedBody)) : "";
  const rawRequestRow = {
    request_id: requestId,
    path,
    method,
    content_type: contentType,
    source_ip_hash: ipHash,
    user_agent_hash: userAgentHash,
    auth_ok: authOk,
    parse_ok: parsed.ok,
    payload_sha256: sha256Hex(rawBody),
    payload_size_bytes: Buffer.byteLength(rawBody || "", "utf8"),
    bundle_version: envelope.bundle_version,
    bundle_type: envelope.bundle_type,
    sent_at_ms: envelope.sent_at_ms,
    record_count: envelope.record_count,
    raw_body: rawBody,
    raw_body_redacted: rawBodyRedacted,
    notes: null,
  };

  const client = await pool.connect();
  let rawRequestId = null;

  try {
    await client.query("begin");
    rawRequestId = await insertRawRequest(client, rawRequestRow);

    if (!parsed.ok) {
      const failure = buildFailureRecord({
        row_type: "ERROR",
        reason: parsed.error,
        request_id: requestId,
        path,
        ip_hash: ipHash,
        user_agent_hash: userAgentHash,
        t_received_ms: tReceivedMs,
        auth_ok: authOk,
        parse_ok: false,
        raw_payload: parsed.raw_preview,
        record_index: 0,
        raw_request_id: rawRequestId,
      });
      await persistFailure(client, failure);

  await client.query("commit");
  return res.status(400).json({ ok: false, error: parsed.error, request_id: requestId });
}

if (queryString) {
  const reason = /(^|[?&])(secret|webhook_secret|webhooksecret|token|authorization|api_key|apikey|password|auth|key)=/i.test("?" + queryString)
    ? "secret_in_query_forbidden"
    : "query_string_forbidden";
  const failure = buildFailureRecord({
    row_type: "INGRESS_REJECT",
    reason,
    request_id: requestId,
    path,
    ip_hash: ipHash,
    user_agent_hash: userAgentHash,
    t_received_ms: tReceivedMs,
    auth_ok: authOk,
    parse_ok: parsed.ok,
    raw_payload: parsed.ok ? "[REDACTED_AT_INGRESS]" : parsed.raw_preview,
    record_index: 0,
    raw_request_id: rawRequestId,
  });
  await persistFailure(client, failure);
  await client.query("commit");
  return res.status(400).json({ ok: false, error: reason, request_id: requestId });
}

    if (/\"secret\"\s*:|\"webhook_secret\"\s*:|\"webhooksecret\"\s*:|\"token\"\s*:|\"authorization\"\s*:/i.test(rawBodyRedacted)) {
      const failure = buildFailureRecord({
        row_type: "ERROR",
        reason: "secret_in_body_forbidden",
        request_id: requestId,
        path,
        ip_hash: ipHash,
        user_agent_hash: userAgentHash,
        t_received_ms: tReceivedMs,
        auth_ok: authOk,
        parse_ok: true,
        raw_payload: "[REDACTED_AT_INGRESS]",
        record_index: 0,
        raw_request_id: rawRequestId,
      });
      await persistFailure(client, failure);
      await client.query("commit");
      return res.status(400).json({ ok: false, error: "secret_in_body_forbidden", request_id: requestId });
    }

    if (!authOk) {
      const failure = buildFailureRecord({
        row_type: "INGRESS_REJECT",
        reason: "source_not_allowed",
        request_id: requestId,
        path,
        ip_hash: ipHash,
        user_agent_hash: userAgentHash,
        t_received_ms: tReceivedMs,
        auth_ok: false,
        parse_ok: true,
        raw_payload: "[REDACTED_AT_INGRESS]",
        record_index: 0,
        raw_request_id: rawRequestId,
      });
      await persistFailure(client, failure);
      await client.query("commit");
      return res.status(403).json({ ok: false, error: "source_not_allowed", request_id: requestId });
    }

    const logicalRecords = expandLogicalRecords(parsedBody);
    if (logicalRecords.length === 0) {
      const failure = buildFailureRecord({
        row_type: "ERROR",
        reason: "no_logical_records_found",
        request_id: requestId,
        path,
        ip_hash: ipHash,
        user_agent_hash: userAgentHash,
        t_received_ms: tReceivedMs,
        auth_ok: authOk,
        parse_ok: true,
        raw_payload: parsedBody,
        record_index: 0,
        raw_request_id: rawRequestId,
      });
      await persistFailure(client, failure);
      await client.query("commit");
      return res.status(400).json({ ok: false, error: "no_logical_records_found", request_id: requestId });
    }

    let inserted = 0;
    for (let index = 0; index < logicalRecords.length; index += 1) {
      const logical = logicalRecords[index];
      const prepared = prepareLogicalRecord(logical, {
        request_id: requestId,
        raw_request_id: rawRequestId,
        record_index: index,
        path,
        ip_hash: ipHash,
        user_agent_hash: userAgentHash,
        t_received_ms: tReceivedMs,
        auth_ok: true,
      });
      await upsertRun(client, prepared);
      await insertRawEvent(client, prepared);
      inserted += 1;
    }

    await client.query("commit");
    return res.json({ ok: true, request_id: requestId, raw_request_id: rawRequestId, inserted });
  } catch (e) {
    await client.query("rollback").catch(() => {});
    console.error("ingest failed:", e);

    try {
      await client.query("begin");
      if (rawRequestId == null) {
        rawRequestId = await insertRawRequest(client, {
          ...rawRequestRow,
          notes: `ingest_exception_pre_row:${e?.message || String(e)}`,
        });
      }
      const failure = buildFailureRecord({
        row_type: "ERROR",
        reason: `ingest_exception:${e?.message || String(e)}`,
        request_id: requestId,
        path,
        ip_hash: ipHash,
        user_agent_hash: userAgentHash,
        t_received_ms: tReceivedMs,
        auth_ok: authOk,
        parse_ok: parsed.ok,
        raw_payload: "[REDACTED_AT_INGRESS]",
        record_index: 0,
        raw_request_id: rawRequestId,
      });
      await persistFailure(client, failure);
      await client.query("commit");
    } catch (e2) {
      await client.query("rollback").catch(() => {});
      console.error("failed to persist ingest exception:", e2);
    }

    return res.status(500).json({ ok: false, error: "ingest_failed", request_id: requestId });
  } finally {
    client.release();
  }
}

app.get("/", (_req, res) => res.status(200).send("ok"));

app.get("/healthz", async (_req, res) => {
  try {
    const rs = await pool.query(`
      select
        (select count(*) from raw_requests) as raw_requests,
        (select count(*) from raw_events) as raw_events
    `);

    return res.json({
      ok: true,
      service: "tv_receiver_secret_free_ingress",
      env: RECEIVER_ENV,
      allow_untrusted_ingress: ALLOW_UNTRUSTED_INGRESS,
      allowed_ip_count: ALLOWED_IP_SET.size,
      database_ok: true,
      counts: rs.rows[0] || {},
      now_utc: new Date().toISOString(),
      paths: ["/tv", "/webhook", "/healthz"],
    });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
});

app.post("/tv", ingestRequest);
app.post("/webhook", ingestRequest);

async function main() {
  await ensureSchema();
  await pool.query("select 1");
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`tv-receiver secret-free ingress listening on ${PORT}`);
  });
}

main().catch((e) => {
  console.error("fatal startup error:", e);
  process.exit(1);
});
