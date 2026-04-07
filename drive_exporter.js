import fs from "fs";
import os from "os";
import path from "path";
import crypto from "crypto";
import pg from "pg";
import { google } from "googleapis";

const { Pool } = pg;

const PACKAGE_VERSION = (() => {
  try {
    const raw = fs.readFileSync(new URL("./package.json", import.meta.url), "utf8");
    const parsed = JSON.parse(raw);
    return String(parsed.version || "0.0.0-unknown");
  } catch {
    return "0.0.0-unknown";
  }
})();

const DATABASE_URL_RAW = (process.env.DATABASE_URL || "").trim();
const CA_CERT = (process.env.CA_CERT || process.env.DATABASE_CA_CERT || "").trim();
const PGSSL_INSECURE = (process.env.PGSSL_INSECURE || "").trim() === "1";
const EXPORTER_ENV = (process.env.EXPORTER_ENV || process.env.RECEIVER_ENV || "prod").trim().toLowerCase();

const GOOGLE_DRIVE_TARGET_MODE = (process.env.GOOGLE_DRIVE_TARGET_MODE || "my_drive_oauth_user").trim();
const GOOGLE_DRIVE_FOLDER_ID = (process.env.GOOGLE_DRIVE_FOLDER_ID || "").trim();
const GOOGLE_DRIVE_FOLDER_PATH_LABEL = (process.env.GOOGLE_DRIVE_FOLDER_PATH_LABEL || "My Drive / Telemetry_Artifacts").trim();
const GOOGLE_OAUTH_CLIENT_ID = (process.env.GOOGLE_OAUTH_CLIENT_ID || "").trim();
const GOOGLE_OAUTH_CLIENT_SECRET = (process.env.GOOGLE_OAUTH_CLIENT_SECRET || "").trim();
const GOOGLE_OAUTH_REFRESH_TOKEN = (process.env.GOOGLE_OAUTH_REFRESH_TOKEN || "").trim();
const GOOGLE_OAUTH_REDIRECT_URI = (process.env.GOOGLE_OAUTH_REDIRECT_URI || "https://developers.google.com/oauthplayground").trim();

const WORKBOOK_HEADERS_PATH = (process.env.WORKBOOK_HEADERS_PATH || "./workbook_headers.json").trim();
const EXPORT_CADENCE_MINUTES = Math.max(1, parseInt(process.env.EXPORT_CADENCE_MINUTES || "60", 10) || 60);
const EXPORT_LATEST_ALIAS = (process.env.EXPORT_LATEST_ALIAS || "1").trim() !== "0";
const EXPORT_XLSX_ENABLED = (process.env.EXPORT_XLSX_ENABLED || "0").trim() === "1";
const EXPORT_TIMEZONE_ID = (process.env.EXPORT_TIMEZONE_ID || "America/Detroit").trim();

const DRIVE_EXPORTER_SLOT_NAME = (process.env.DRIVE_EXPORTER_SLOT_NAME || "main").trim();
const DRIVE_EXPORTER_BATCH_SIZE = Math.min(
  5000,
  Math.max(25, parseInt(process.env.DRIVE_EXPORTER_BATCH_SIZE || "500", 10) || 500)
);
const DRIVE_EXPORTER_INCLUDE_RAW_REQUEST_SUMMARY = (process.env.DRIVE_EXPORTER_INCLUDE_RAW_REQUEST_SUMMARY || "0").trim() === "1";
const DRIVE_EXPORTER_SKIP_DRIVE_UPLOAD = (process.env.DRIVE_EXPORTER_SKIP_DRIVE_UPLOAD || "0").trim() === "1";
const DRIVE_EXPORTER_LOCAL_OUTPUT_DIR = (process.env.DRIVE_EXPORTER_LOCAL_OUTPUT_DIR || "").trim();
const DRIVE_RUNS_FOLDER_NAME = (process.env.DRIVE_RUNS_FOLDER_NAME || "runs").trim();
const DRIVE_LATEST_FOLDER_NAME = (process.env.DRIVE_LATEST_FOLDER_NAME || "latest").trim();

const EXPECTED_DRIVE_TARGET_MODE = "my_drive_oauth_user";
const EXPECTED_STREAMS = ["B1M", "B2M_AP", "B3M_PIVOTS"];
const DETAIL_ARTIFACT_NAMES = [
  "B1M_CONFIG.csv",
  "B1M_BAR.csv",
  "B1M_EVAL.csv",
  "B1M_BAR_CSV_WIDE.csv",
  "B2M_CONFIG.csv",
  "B2M_BAR.csv",
  "B2M_EVAL.csv",
  "B2M_BAR_CSV_WIDE.csv",
  "B3M_CONFIG.csv",
  "B3M_BAR.csv",
  "B3M_EVAL.csv",
  "B3M_BAR_CSV_WIDE.csv",
];
const REQUIRED_ARTIFACT_ORDER = [
  "README.txt",
  "STREAM_KEY.csv",
  "DATA_DICTIONARY.csv",
  "LEDGER.csv",
  ...DETAIL_ARTIFACT_NAMES,
];
const LOCK_KEY = 7300410073004100n;

if (!DATABASE_URL_RAW) {
  console.error("FATAL: DATABASE_URL is not set");
  process.exit(1);
}
if (!CA_CERT && !PGSSL_INSECURE) {
  console.error("FATAL: DATABASE_CA_CERT (or CA_CERT) is required unless PGSSL_INSECURE=1 for DEV only");
  process.exit(1);
}
if (PGSSL_INSECURE && EXPORTER_ENV === "prod") {
  console.error("FATAL: PGSSL_INSECURE=1 is forbidden when EXPORTER_ENV=prod");
  process.exit(1);
}
if (GOOGLE_DRIVE_TARGET_MODE !== EXPECTED_DRIVE_TARGET_MODE) {
  console.error(`FATAL: GOOGLE_DRIVE_TARGET_MODE must be ${EXPECTED_DRIVE_TARGET_MODE}`);
  process.exit(1);
}
if (EXPORTER_ENV === "prod" && EXPORT_XLSX_ENABLED) {
  console.error("FATAL: EXPORT_XLSX_ENABLED=1 is forbidden in this contract stage");
  process.exit(1);
}
if (!DRIVE_EXPORTER_SKIP_DRIVE_UPLOAD && !GOOGLE_DRIVE_FOLDER_ID) {
  console.error("FATAL: GOOGLE_DRIVE_FOLDER_ID is not set");
  process.exit(1);
}
if (!DRIVE_EXPORTER_SKIP_DRIVE_UPLOAD && (!GOOGLE_OAUTH_CLIENT_ID || !GOOGLE_OAUTH_CLIENT_SECRET || !GOOGLE_OAUTH_REFRESH_TOKEN)) {
  console.error("FATAL: GOOGLE_OAUTH_CLIENT_ID, GOOGLE_OAUTH_CLIENT_SECRET, and GOOGLE_OAUTH_REFRESH_TOKEN are required");
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
  max: 5,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 10_000,
});

function sha256Hex(value) {
  const h = crypto.createHash("sha256");
  h.update(typeof value === "string" ? value : JSON.stringify(value ?? null));
  return h.digest("hex");
}

function cloneJson(value) {
  if (value === null || value === undefined) return null;
  return JSON.parse(JSON.stringify(value));
}

function safeString(value) {
  if (value === null || value === undefined) return "";
  return String(value);
}

function safeNumberOrString(value) {
  if (value === null || value === undefined || value === "") return "";
  if (typeof value === "number") return Number.isFinite(value) ? value : "";
  if (typeof value === "bigint") return value.toString();
  const s = String(value);
  const n = Number(s);
  return Number.isNaN(n) ? s : n;
}

function clampForCell(text) {
  if (text === null || text === undefined) return "";
  const s = String(text);
  return s.length > 49000 ? s.slice(0, 49000) + " …[TRUNCATED]" : s;
}

function escapeLeadingFormulaChars(text) {
  if (text === null || text === undefined) return "";
  const s = String(text);
  return /^[=+\-@]/.test(s) ? ("'" + s) : s;
}

function sanitizeCell(value) {
  if (value === null || value === undefined) return "";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") return Number.isFinite(value) ? String(value) : "";
  if (typeof value === "bigint") return value.toString();
  if (Object.prototype.toString.call(value) === "[object Date]") return value.toISOString();
  if (typeof value === "object") return clampForCell(escapeLeadingFormulaChars(JSON.stringify(value)));
  return clampForCell(escapeLeadingFormulaChars(String(value)));
}

function csvCell(value) {
  const s = sanitizeCell(value).replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  if (/[",\n]/.test(s)) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

function csvLine(values) {
  return values.map(csvCell).join(",");
}

function sortStrings(values) {
  return [...values].filter(Boolean).sort((a, b) => String(a).localeCompare(String(b)));
}

function toBigInt(value) {
  if (typeof value === "bigint") return value;
  if (value === null || value === undefined || value === "") return 0n;
  try {
    return BigInt(String(value));
  } catch {
    return 0n;
  }
}

function toIso(value) {
  if (value instanceof Date) return value.toISOString();
  if (value === null || value === undefined || value === "") return "";
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? "" : d.toISOString();
}

function toTimestampSlug(date) {
  return date.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");
}

function localTimestamp(date, timeZone) {
  try {
    const formatter = new Intl.DateTimeFormat("en-US", {
      timeZone,
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    });
    return formatter.format(date);
  } catch {
    return date.toISOString();
  }
}

function parseCsvLineWithSep(line, sep) {
  const out = [];
  let cur = "";
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (inQuotes) {
      if (ch === '"') {
        if (i + 1 < line.length && line[i + 1] === '"') {
          cur += '"';
          i += 1;
        } else {
          inQuotes = false;
        }
      } else {
        cur += ch;
      }
    } else if (ch === '"') {
      inQuotes = true;
    } else if (ch === sep) {
      out.push(cur);
      cur = "";
    } else {
      cur += ch;
    }
  }
  out.push(cur);
  return out;
}

function parseCsvLine(line, expectedCount, preferredSep = "") {
  const candidates = [];
  if (preferredSep && preferredSep.length === 1) candidates.push(preferredSep);
  for (const c of [",", ";", "\t", "|"]) {
    if (!candidates.includes(c)) candidates.push(c);
  }

  let bestParts = parseCsvLineWithSep(line, candidates[0] || ",");
  if (expectedCount && bestParts.length === expectedCount) return bestParts;

  for (let i = 1; i < candidates.length; i++) {
    const parts = parseCsvLineWithSep(line, candidates[i]);
    if (expectedCount && parts.length === expectedCount) return parts;
    if (parts.length > bestParts.length) bestParts = parts;
  }

  return bestParts;
}

function rowFromHeaders(headers, obj) {
  return headers.map((h) => sanitizeCell(obj[h]));
}

function loadHeaders() {
  const raw = fs.readFileSync(WORKBOOK_HEADERS_PATH, "utf8");
  return JSON.parse(raw);
}

function assertContractHeaders(headersByTab) {
  const requiredTabs = [
    "LEDGER",
    "B1M_CONFIG", "B1M_BAR", "B1M_EVAL", "B1M_BAR_CSV_WIDE",
    "B2M_CONFIG", "B2M_BAR", "B2M_EVAL", "B2M_BAR_CSV_WIDE",
    "B3M_CONFIG", "B3M_BAR", "B3M_EVAL", "B3M_BAR_CSV_WIDE",
  ];

  for (const tabName of requiredTabs) {
    if (!headersByTab[tabName]) throw new Error(`Missing governed header definition: ${tabName}`);
  }

  const requiredColumnsByTab = {
    B2M_CONFIG: ["include_csv_in_json", "sep", "csv_col_count", "csv_header"],
    B3M_CONFIG: ["include_csv_in_json", "sep", "csv_col_count", "csv_header"],
    B2M_BAR: ["csv"],
    B3M_BAR: ["csv"],
    B1M_BAR_CSV_WIDE: ["csv_parse_ok", "csv_field_count"],
    B2M_BAR_CSV_WIDE: ["csv_parse_ok", "csv_field_count"],
    B3M_BAR_CSV_WIDE: ["csv_parse_ok", "csv_field_count"],
  };

  for (const [tabName, requiredColumns] of Object.entries(requiredColumnsByTab)) {
    const headers = headersByTab[tabName] || [];
    for (const columnName of requiredColumns) {
      if (!headers.includes(columnName)) {
        throw new Error(`Governed header mismatch: ${tabName} is missing required column ${columnName}`);
      }
    }
  }
}

function detectStreamId(rec) {
  const joined = [
    rec.stream_id,
    rec.producer_id,
    rec.producer,
    rec.log_tag,
    rec.event_type,
    rec.script_id,
    rec.universe_id,
  ].filter(Boolean).join(" ");
  if (/B3M_PIVOTS/i.test(joined)) return "B3M_PIVOTS";
  if (/B2M_AP/i.test(joined)) return "B2M_AP";
  if (/B1M/i.test(joined)) return "B1M";
  return "UNKNOWN";
}

function producerIdFromStream(streamId) {
  if (streamId === "B1M") return "B1M";
  if (streamId === "B2M_AP") return "B2M";
  if (streamId === "B3M_PIVOTS") return "B3M";
  return "UNKNOWN";
}

function analysisRole(streamId, rowType) {
  if (rowType === "CONFIG") return "PROVENANCE";
  if (rowType === "EVAL") return "POST_HOC_EVAL";
  if (rowType !== "BAR") return "UNKNOWN";
  if (streamId === "B1M") return "MARKET_STATE";
  if (streamId === "B2M_AP") return "MOMENTUM_STATE";
  if (streamId === "B3M_PIVOTS") return "LEVEL_STATE";
  return "UNKNOWN";
}

function defaultEventType(streamId, rowType) {
  if (rowType !== "CONFIG") return "";
  if (streamId === "B1M") return "B1M_CONFIG";
  if (streamId === "B2M_AP") return "B2M_AP_CONFIG";
  if (streamId === "B3M_PIVOTS") return "B3M_PIVOTS_CONFIG";
  return "";
}

function normalizeRecord(rec, requestId, recordIndex, ingestTs) {
  const streamId = detectStreamId(rec);
  const producerId = safeString(rec.producer_id || producerIdFromStream(streamId));
  const rowType = safeString(rec.row_type || "UNKNOWN");
  const cfgSigFull = safeString(rec.cfg_sig_full || "");
  const cfgSigRaw = safeString(rec.cfg_sig_raw || rec.cfg_sig || "");
  const canonicalBarUid = safeString(
    rec.bar_uid_canonical ||
    rec.parent_bar_uid_canonical ||
    ((streamId === "B1M" && rowType === "BAR") ? rec.uid : "") ||
    ((streamId === "B1M" && rowType === "EVAL") ? rec.parent_uid : "")
  );
  const rawJson = clampForCell(JSON.stringify(rec));
  const out = { ...rec };

  out.request_id = requestId;
  out.record_index = recordIndex;
  out.ingest_ts_utc = ingestTs;
  out.stream_id = streamId;
  out.producer_id = producerId;
  out.row_type = rowType;
  out.event_type = safeString(rec.event_type || defaultEventType(streamId, rowType));
  out.uid = safeString(rec.uid || (requestId + "|" + recordIndex));
  out.dedup = safeString(rec.dedup || out.uid);
  out.parent_uid = safeString(rec.parent_uid || "");
  out.bar_uid_canonical = canonicalBarUid;
  out.run_id = safeString(rec.run_id || "");
  out.cfg_sig_raw = cfgSigRaw;
  out.cfg_sig_full = cfgSigFull;
  out.cfg_sig_sha256_local = cfgSigFull ? sha256Hex(cfgSigFull) : safeString(rec.cfg_sig_sha256 || "");
  out.schema_version = safeString(rec.schema_version || "");
  out.json_schema_version = safeString(rec.json_schema_version || "");
  out.wide_schema_version = safeString(rec.wide_schema_version || "");
  out.csv_schema_version = safeString(rec.csv_schema_version || "");
  out.schema_registry_version = safeString(rec.schema_registry_version || "");
  out.schema_registry_hash = safeString(rec.schema_registry_hash || "");
  out.script_id = safeString(rec.script_id || "");
  out.script_sha = safeString(rec.script_sha || "");
  out.alert_tag = safeString(rec.alert_tag || "");
  out.env = safeString(rec.env || "");
  out.deployment_id = safeString(rec.deployment_id || "");
  out.exchange = safeString(rec.exchange || "");
  out.symbol = safeString(rec.symbol || "");
  out.symbol_native = safeString(rec.symbol_native || rec.symbol || "");
  out.tickerid = safeString(rec.tickerid || "");
  out.instrument_type = safeString(rec.instrument_type || "");
  out.tf = safeString(rec.tf || "");
  out.tf_sec = safeNumberOrString(rec.tf_sec);
  out.t_subject_ms = safeNumberOrString(rec.t_subject_ms);
  out.t_open_ms = safeNumberOrString(rec.t_open_ms);
  out.t_close_ms = safeNumberOrString(rec.t_close_ms);
  out.t_eval_close_ms = safeNumberOrString(rec.t_eval_close_ms);
  out.t_event_ms = safeNumberOrString(rec.t_event_ms);
  out.seq = safeNumberOrString(rec.seq);
  out.time_basis = safeString(rec.time_basis || "");
  out.price_quote = safeString(rec.price_quote || "");
  out.contracts_def = safeString(rec.contracts_def || "");
  out.base_weight = 1;
  out.analysis_eligible = rowType === "BAR";
  out.analysis_role = analysisRole(streamId, rowType);
  out.parse_status = streamId === "UNKNOWN" ? "UNKNOWN_STREAM_RETAINED" : "PARSED";
  out.raw_json = rawJson;
  return out;
}

function buildCsvWideRowObject(tabName, norm, headersByTab) {
  const headers = headersByTab[tabName];
  const row = {
    request_id: norm.request_id,
    record_index: norm.record_index,
    ingest_ts_utc: norm.ingest_ts_utc,
    stream_id: norm.stream_id,
    uid: norm.uid,
    symbol: norm.symbol,
    tickerid: norm.tickerid,
    tf: norm.tf,
    t_subject_ms: norm.t_subject_ms,
    csv_parse_ok: false,
    csv_field_count: 0,
  };

  const csvLine = safeString(norm.csv || "");
  if (!csvLine) {
    return { row, values: rowFromHeaders(headers, row) };
  }

  const csvHeaders = headers.slice(11);
  const preferredSep = safeString(norm.sep || "").slice(0, 1);
  const parts = parseCsvLine(csvLine, csvHeaders.length, preferredSep);
  row.csv_field_count = parts.length;
  row.csv_parse_ok = parts.length === csvHeaders.length;
  for (let i = 0; i < csvHeaders.length; i++) {
    row[csvHeaders[i]] = i < parts.length ? parts[i] : "";
  }

  return { row, values: rowFromHeaders(headers, row) };
}

function streamPrefix(streamId) {
  if (streamId === "B1M") return "B1M";
  if (streamId === "B2M_AP") return "B2M";
  if (streamId === "B3M_PIVOTS") return "B3M";
  return "UNKNOWN";
}

function detailArtifactName(streamId, rowType) {
  const prefix = streamPrefix(streamId);
  if (prefix === "UNKNOWN") return "";
  if (rowType === "CONFIG") return `${prefix}_CONFIG.csv`;
  if (rowType === "BAR") return `${prefix}_BAR.csv`;
  if (rowType === "EVAL") return `${prefix}_EVAL.csv`;
  return "";
}

function csvWideArtifactName(streamId) {
  const prefix = streamPrefix(streamId);
  if (prefix === "UNKNOWN") return "";
  return `${prefix}_BAR_CSV_WIDE.csv`;
}

function dictionarySourceStream(artifactName) {
  if (/^B1M/.test(artifactName)) return "B1M";
  if (/^B2M/.test(artifactName)) return "B2M_AP";
  if (/^B3M/.test(artifactName)) return "B3M_PIVOTS";
  if (artifactName === "LEDGER.csv") return "COMMON";
  return "COMMON";
}

function humanizeColumnName(columnName) {
  return String(columnName || "")
    .replace(/_/g, " ")
    .replace(/\bcfg\b/gi, "config")
    .replace(/\buid\b/gi, "UID");
}

function defaultDictionaryMeaning(artifactName, columnName) {
  if (columnName === "csv") return "Raw BAR csv line as emitted by the producer payload for this record.";
  if (columnName === "csv_parse_ok") return "True when the raw csv field parsed to the governed number of columns for this artifact.";
  if (columnName === "csv_field_count") return "Number of parsed csv fields detected in the raw csv line.";
  if (columnName === "raw_json") return "JSON rendering of the retained logical record for audit and review.";
  if (columnName === "cfg_sig") return "Configuration signature emitted by the producer for this run/configuration.";
  if (columnName === "cfg_sig_raw") return "Raw configuration signature as received from the producer.";
  if (columnName === "cfg_sig_full") return "Expanded configuration signature payload preserved for hash/audit use.";
  if (columnName === "cfg_sig_sha256_local") return "Local sha256 representation of the configuration signature when available.";
  if (columnName === "request_id") return "Receiver-generated identifier for the HTTP ingress request.";
  if (columnName === "record_index") return "Zero-based position of the logical record inside the parsed request payload.";
  if (columnName === "stream_id") return "Governed stream identifier after normalization.";
  if (columnName === "row_type") return "Logical row class such as CONFIG, BAR, or EVAL.";
  if (columnName === "event_type") return "Event subtype carried or derived for the logical row.";
  if (columnName === "uid") return "Primary logical row identifier preserved for audit and joins.";
  if (columnName === "dedup") return "Producer-side deduplication key or fallback UID.";
  if (columnName === "bar_uid_canonical") return "Canonical B1M-style bar UID used for cross-stream joins.";
  if (columnName.endsWith("_ms")) return `${humanizeColumnName(columnName)} timestamp in UTC milliseconds.`;
  if (columnName.endsWith("_csv")) return "Delimited text field preserved exactly as emitted by the producer.";
  return `Governed field: ${humanizeColumnName(columnName)}.`;
}

function defaultDictionaryUnits(columnName) {
  if (/_ms$/.test(columnName)) return "ms UTC";
  if (/_pct$/.test(columnName)) return "%";
  if (/_count$/.test(columnName) || /^(seq|record_index|bar_index|tf_sec|csv_field_count)$/.test(columnName)) return "count";
  if (/(^open$|^high$|^low$|^close$|_price$|_value$|_line$|_anchor$|_center$|_near$|_far$|_diff$|_res$|_sup$|_atr$|_slope$|_delta$|_eps$|_measure$)/.test(columnName)) return "producer native units";
  if (/(^volume$|_volume$)/.test(columnName)) return "producer native volume units";
  if (/(^csv_parse_ok$|_any$|_final$|_valid$|_eligible$|_ok$|^parse_ok$)/.test(columnName)) return "flag";
  return "";
}

function defaultDictionaryType(columnName) {
  if (/_ms$/.test(columnName) || /(_count$|^(seq|record_index|bar_index|tf_sec|csv_field_count|kernel_state|ml_signal)$)/.test(columnName)) return "integer";
  if (/(^csv_parse_ok$|_any$|_final$|_valid$|_eligible$|_ok$|^parse_ok$)/.test(columnName)) return "boolean/flag";
  if (columnName === "raw_json" || columnName === "csv" || columnName.endsWith("_csv") || /(uid|dedup|symbol|tickerid|event_type|producer|stream_id|row_type|alert_tag|cfg_sig|time_basis|env|deployment_id|timezone_id|instrument_type|price_quote|contracts_def|exchange|source_family|research_profile|compression_note|meaning|notes|log_tag|emit_mode|emit_reason)/.test(columnName)) return "string";
  return "number/string";
}

function defaultDictionaryNotes(artifactName, columnName, isCsvWide) {
  if (isCsvWide && !/^request_id$|^record_index$|^ingest_ts_utc$|^stream_id$|^uid$|^symbol$|^tickerid$|^tf$|^t_subject_ms$|^csv_parse_ok$|^csv_field_count$/.test(columnName)) {
    return "Parsed from the BAR.csv field for this stream when present. Column order is governed by the producer csv header definition for this stream.";
  }
  if (columnName === "csv") return "This raw BAR csv string is also the source material for the matching *_BAR_CSV_WIDE.csv artifact when present.";
  if (columnName === "raw_json") return "Retained as text for audit/review; large values may be truncated for spreadsheet safety.";
  if (artifactName === "LEDGER.csv") return "Normalized cross-stream ledger row.";
  return "";
}

function buildDataDictionaryRows(headersByArtifact) {
  const rows = [["artifact_name", "column_name", "meaning", "units", "source_stream", "data_type", "notes"]];
  for (const artifactName of ["LEDGER.csv", ...DETAIL_ARTIFACT_NAMES]) {
    const headerKey = artifactName.replace(/\.csv$/, "");
    const headers = headersByArtifact[headerKey] || [];
    const sourceStream = dictionarySourceStream(artifactName);
    const isCsvWide = /_BAR_CSV_WIDE\.csv$/.test(artifactName);
    for (const columnName of headers) {
      rows.push([
        artifactName,
        columnName,
        defaultDictionaryMeaning(artifactName, columnName),
        defaultDictionaryUnits(columnName),
        sourceStream,
        defaultDictionaryType(columnName),
        defaultDictionaryNotes(artifactName, columnName, isCsvWide),
      ]);
    }
  }
  return rows;
}

class ArtifactWriter {
  constructor(filePath, headers) {
    this.filePath = filePath;
    this.headers = headers;
    this.hash = crypto.createHash("sha256");
    this.rows = 0;
    this.bytes = 0;
    this.stream = fs.createWriteStream(filePath, { encoding: "utf8" });
    this.writeValues(headers);
  }

  writeValues(values) {
    const line = csvLine(values) + "\n";
    this.stream.write(line);
    this.hash.update(line);
    this.bytes += Buffer.byteLength(line, "utf8");
  }

  writeRowObject(obj) {
    this.writeValues(this.headers.map((h) => obj[h]));
    this.rows += 1;
  }

  writeRowArray(values) {
    this.writeValues(values);
    this.rows += 1;
  }

  async close() {
    await new Promise((resolve, reject) => {
      this.stream.end((err) => (err ? reject(err) : resolve()));
    });
    return {
      sha256: this.hash.digest("hex"),
      size_bytes: this.bytes,
      row_count: this.rows,
    };
  }
}

async function dbQuery(sql, params = []) {
  const client = await pool.connect();
  try {
    return await client.query(sql, params);
  } finally {
    client.release();
  }
}

async function tableExists(tableName) {
  const rs = await dbQuery("select to_regclass($1) is not null as ok", [`public.${tableName}`]);
  return Boolean(rs.rows[0]?.ok);
}

async function tableColumns(tableName) {
  const rs = await dbQuery(`
    select column_name
    from information_schema.columns
    where table_schema = 'public' and table_name = $1
    order by ordinal_position
  `, [tableName]);
  return new Set(rs.rows.map((r) => String(r.column_name)));
}

async function ensureExporterSchema() {
  await dbQuery(`
    create table if not exists artifact_export_slots (
      slot_name text primary key,
      last_successful_source_watermark bigint,
      last_started_at timestamptz,
      last_finished_at timestamptz,
      last_status text,
      last_error text,
      latest_folder_id text,
      immutable_folder_id text,
      latest_manifest_file_id text,
      updated_at timestamptz not null default now()
    );
  `);

  await dbQuery(`
    create table if not exists artifact_export_runs (
      id bigserial primary key,
      export_id text not null unique,
      slot_name text not null references artifact_export_slots(slot_name) on delete cascade,
      started_at timestamptz not null default now(),
      finished_at timestamptz,
      status text not null default 'STARTED',
      source_watermark bigint not null default 0,
      previous_successful_watermark bigint,
      cadence_minutes integer not null,
      latest_alias_enabled boolean not null default true,
      xlsx_enabled boolean not null default false,
      timezone_id text,
      drive_target_mode text,
      drive_root_folder_id text,
      immutable_folder_id text,
      latest_folder_id text,
      manifest_file_id text,
      exported_file_count integer not null default 0,
      exported_artifact_count integer not null default 0,
      total_row_count bigint not null default 0,
      note text,
      manifest jsonb
    );
  `);

  await dbQuery(`create index if not exists artifact_export_runs_slot_started_idx on artifact_export_runs (slot_name, started_at desc);`);
  await dbQuery(`create index if not exists artifact_export_runs_status_idx on artifact_export_runs (status, started_at desc);`);

  await dbQuery(`
    create table if not exists artifact_export_files (
      run_id bigint not null references artifact_export_runs(id) on delete cascade,
      phase text not null,
      logical_name text not null,
      mime_type text not null,
      sha256 text not null,
      size_bytes bigint not null default 0,
      row_count bigint,
      drive_file_id text,
      drive_parent_id text,
      created_at timestamptz not null default now(),
      primary key (run_id, phase, logical_name)
    );
  `);
}

async function acquireExporterLock() {
  const rs = await dbQuery("select pg_try_advisory_lock($1) as ok", [LOCK_KEY.toString()]);
  return Boolean(rs.rows[0]?.ok);
}

async function releaseExporterLock() {
  await dbQuery("select pg_advisory_unlock($1)", [LOCK_KEY.toString()]).catch(() => {});
}

async function getSlotState(slotName) {
  await dbQuery(`
    insert into artifact_export_slots (slot_name)
    values ($1)
    on conflict (slot_name) do nothing;
  `, [slotName]);

  const rs = await dbQuery(`
    select slot_name, last_successful_source_watermark, last_started_at, last_finished_at,
           last_status, last_error, latest_folder_id, immutable_folder_id, latest_manifest_file_id
    from artifact_export_slots
    where slot_name = $1
  `, [slotName]);
  return rs.rows[0] || null;
}

async function markSlotStarted(slotName) {
  await dbQuery(`
    update artifact_export_slots
    set last_started_at = now(), last_status = 'STARTED', last_error = null, updated_at = now()
    where slot_name = $1
  `, [slotName]);
}

async function createRunRow(slotName, exportId, sourceWatermark, previousSuccessfulWatermark) {
  const rs = await dbQuery(`
    insert into artifact_export_runs (
      export_id,
      slot_name,
      source_watermark,
      previous_successful_watermark,
      cadence_minutes,
      latest_alias_enabled,
      xlsx_enabled,
      timezone_id,
      drive_target_mode,
      drive_root_folder_id
    )
    values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
    returning id
  `, [
    exportId,
    slotName,
    sourceWatermark.toString(),
    previousSuccessfulWatermark ? previousSuccessfulWatermark.toString() : null,
    EXPORT_CADENCE_MINUTES,
    EXPORT_LATEST_ALIAS,
    EXPORT_XLSX_ENABLED,
    EXPORT_TIMEZONE_ID,
    GOOGLE_DRIVE_TARGET_MODE,
    GOOGLE_DRIVE_FOLDER_ID || null,
  ]);
  return rs.rows[0].id;
}

async function noteArtifactFiles(runId, phase, files) {
  for (const file of files) {
    await dbQuery(`
      insert into artifact_export_files (
        run_id, phase, logical_name, mime_type, sha256, size_bytes, row_count, drive_file_id, drive_parent_id
      )
      values ($1,$2,$3,$4,$5,$6,$7,$8,$9)
      on conflict (run_id, phase, logical_name)
      do update set
        mime_type = excluded.mime_type,
        sha256 = excluded.sha256,
        size_bytes = excluded.size_bytes,
        row_count = excluded.row_count,
        drive_file_id = excluded.drive_file_id,
        drive_parent_id = excluded.drive_parent_id,
        created_at = now()
    `, [
      runId,
      phase,
      file.logical_name,
      file.mime_type,
      file.sha256,
      String(file.size_bytes || 0),
      file.row_count == null ? null : String(file.row_count),
      file.drive_file_id || null,
      file.drive_parent_id || null,
    ]);
  }
}

async function markRunSuccess(runId, manifest, publicationSummary, uploadedFiles) {
  const totalRowCount = uploadedFiles
    .filter((x) => x.row_count != null)
    .reduce((sum, x) => sum + Number(x.row_count || 0), 0);

  await dbQuery(`
    update artifact_export_runs
    set finished_at = now(),
        status = $2,
        immutable_folder_id = $3,
        latest_folder_id = $4,
        manifest_file_id = $5,
        exported_file_count = $6,
        exported_artifact_count = $7,
        total_row_count = $8,
        note = $9,
        manifest = $10::jsonb
    where id = $1
  `, [
    runId,
    manifest.status || "OK",
    publicationSummary.immutable_folder_id || null,
    publicationSummary.latest_folder_id || null,
    publicationSummary.latest_manifest_file_id || publicationSummary.immutable_manifest_file_id || null,
    uploadedFiles.length,
    manifest.artifacts.length,
    totalRowCount,
    publicationSummary.note || null,
    JSON.stringify(manifest),
  ]);

  await dbQuery(`
    update artifact_export_slots
    set last_successful_source_watermark = $2,
        last_finished_at = now(),
        last_status = $3,
        last_error = null,
        latest_folder_id = $4,
        immutable_folder_id = $5,
        latest_manifest_file_id = $6,
        updated_at = now()
    where slot_name = $1
  `, [
    DRIVE_EXPORTER_SLOT_NAME,
    String(manifest.source_watermark.materializer_last_raw_event_id || 0),
    manifest.status || "OK",
    publicationSummary.latest_folder_id || null,
    publicationSummary.immutable_folder_id || null,
    publicationSummary.latest_manifest_file_id || publicationSummary.immutable_manifest_file_id || null,
  ]);
}

async function markRunFailure(runId, err) {
  const note = `${err?.name || "Error"}: ${err?.message || String(err)}`;
  if (runId) {
    await dbQuery(`
      update artifact_export_runs
      set finished_at = now(), status = 'FAILED', note = $2
      where id = $1
    `, [runId, note]).catch(() => {});
  }

  await dbQuery(`
    update artifact_export_slots
    set last_finished_at = now(), last_status = 'FAILED', last_error = $2, updated_at = now()
    where slot_name = $1
  `, [DRIVE_EXPORTER_SLOT_NAME, note]).catch(() => {});
}

async function requireMaterializerState() {
  const hasState = await tableExists("materializer_state");
  if (!hasState) throw new Error("materializer_state table is missing; materializer has not been reinstated yet");
  const rs = await dbQuery(`select last_raw_event_id from materializer_state where id = 1`);
  if (!rs.rowCount) throw new Error("materializer_state row id=1 is missing");
  return toBigInt(rs.rows[0].last_raw_event_id);
}

async function fetchTableCounts(sourceWatermark) {
  const [configs, bars, evals] = await Promise.all([
    dbQuery(`select count(*)::bigint as n from configs where raw_event_id <= $1`, [sourceWatermark.toString()]),
    dbQuery(`select count(*)::bigint as n from bars where raw_event_id <= $1`, [sourceWatermark.toString()]),
    dbQuery(`select count(*)::bigint as n from evals where raw_event_id <= $1`, [sourceWatermark.toString()]),
  ]);
  return {
    configs: Number(configs.rows[0]?.n || 0),
    bars: Number(bars.rows[0]?.n || 0),
    evals: Number(evals.rows[0]?.n || 0),
  };
}

async function fetchNonMaterializedCounts(sourceWatermark) {
  if (!(await tableExists("raw_events"))) return {};
  const rs = await dbQuery(`
    select coalesce(row_type, 'NULL') as row_type, count(*)::bigint as n
    from raw_events
    where id <= $1
      and coalesce(row_type, '') not in ('CONFIG', 'BAR', 'EVAL')
    group by coalesce(row_type, 'NULL')
    order by coalesce(row_type, 'NULL') asc
  `, [sourceWatermark.toString()]);
  const out = {};
  for (const row of rs.rows) out[String(row.row_type)] = Number(row.n || 0);
  return out;
}

async function makeRawEventsCompatibilityInfo() {
  const cols = await tableColumns("raw_events");
  return {
    rawEventsHasRecordIndex: cols.has("record_index"),
  };
}

async function fetchMaterializedBatch(tableName, rowType, sourceWatermark, cursor, batchSize, compatibility) {
  const recordIndexExpr = compatibility.rawEventsHasRecordIndex
    ? "re.record_index"
    : "null::integer as record_index";

  const sql = `
    select
      t.raw_event_id,
      t.uid,
      t.request_id,
      t.received_at,
      ${recordIndexExpr},
      t.payload,
      to_jsonb(t) - 'payload' as meta
    from ${tableName} t
    left join raw_events re on re.id = t.raw_event_id
    where t.raw_event_id <= $1
      and (
        t.raw_event_id > $2
        or (t.raw_event_id = $2 and t.uid > $3)
      )
    order by t.raw_event_id asc, t.uid asc
    limit $4
  `;

  const rs = await dbQuery(sql, [
    sourceWatermark.toString(),
    cursor.lastRawEventId.toString(),
    cursor.lastUid,
    batchSize,
  ]);

  const rows = rs.rows || [];
  const nextCursor = rows.length
    ? {
        lastRawEventId: toBigInt(rows[rows.length - 1].raw_event_id),
        lastUid: safeString(rows[rows.length - 1].uid),
      }
    : cursor;

  return { rows, nextCursor, rowType };
}

function logicalRecordFromMaterializedRow(row, rowType) {
  const payload = row.payload && typeof row.payload === "object" ? cloneJson(row.payload) : {};
  const meta = row.meta && typeof row.meta === "object" ? cloneJson(row.meta) : {};
  const logical = {
    ...payload,
    ...meta,
  };
  logical.row_type = rowType;
  logical.request_id = safeString(row.request_id || logical.request_id || "");
  logical.record_index = row.record_index ?? logical.record_index ?? 0;
  logical.uid = safeString(row.uid || logical.uid || "");
  return logical;
}

function ensureStreamStatsEntry(streamStats, streamId) {
  if (!streamStats.has(streamId)) {
    streamStats.set(streamId, {
      producerIds: new Set(),
      producerVersions: new Set(),
      scriptIds: new Set(),
      scriptShas: new Set(),
      observedRowTypes: new Set(),
    });
  }
  return streamStats.get(streamId);
}

function noteStreamObservation(streamStats, norm) {
  const streamId = safeString(norm.stream_id || "UNKNOWN") || "UNKNOWN";
  const stat = ensureStreamStatsEntry(streamStats, streamId);
  if (norm.producer_id) stat.producerIds.add(norm.producer_id);
  if (norm.producer_version) stat.producerVersions.add(norm.producer_version);
  if (norm.script_id) stat.scriptIds.add(norm.script_id);
  if (norm.script_sha) stat.scriptShas.add(norm.script_sha);
  if (norm.row_type) stat.observedRowTypes.add(norm.row_type);
}

function bumpNestedCounter(target, key1, key2) {
  if (!target[key1]) target[key1] = {};
  target[key1][key2] = (target[key1][key2] || 0) + 1;
}

function createGapCounters() {
  const out = {};
  for (const stream of EXPECTED_STREAMS) {
    out[stream] = {
      bar_rows: 0,
      missing_csv: 0,
      parse_mismatch: 0,
      bars_missing_config: 0,
      evals_missing_config: 0,
    };
  }
  return out;
}

function appendKnownGap(messages, condition, text) {
  if (condition) messages.push(text);
}

async function exportTableToArtifacts(tableName, rowType, sourceWatermark, compatibility, headersByTab, writers, streamStats, gapCounters, unknownStreamCounts) {
  let cursor = { lastRawEventId: 0n, lastUid: "" };

  for (;;) {
    const batch = await fetchMaterializedBatch(tableName, rowType, sourceWatermark, cursor, DRIVE_EXPORTER_BATCH_SIZE, compatibility);
    if (!batch.rows.length) break;

    for (const row of batch.rows) {
      const logical = logicalRecordFromMaterializedRow(row, rowType);
      const requestId = safeString(row.request_id || logical.request_id || row.uid || "UNKNOWN_REQUEST");
      const recordIndex = row.record_index === null || row.record_index === undefined ? 0 : Number(row.record_index);
      const ingestTs = toIso(row.received_at);
      const norm = normalizeRecord(logical, requestId, recordIndex, ingestTs);
      noteStreamObservation(streamStats, norm);

      writers["LEDGER.csv"].writeRowArray(rowFromHeaders(headersByTab.LEDGER, norm));

      const detailName = detailArtifactName(norm.stream_id, rowType);
      if (detailName && writers[detailName]) {
        const tabName = detailName.replace(/\.csv$/, "");
        writers[detailName].writeRowArray(rowFromHeaders(headersByTab[tabName], norm));
      } else {
        unknownStreamCounts[norm.stream_id || "UNKNOWN"] = (unknownStreamCounts[norm.stream_id || "UNKNOWN"] || 0) + 1;
      }

      if (rowType === "BAR") {
        if (gapCounters[norm.stream_id]) gapCounters[norm.stream_id].bar_rows += 1;
        if (logical.config_present === false && gapCounters[norm.stream_id]) {
          gapCounters[norm.stream_id].bars_missing_config += 1;
        }

        const wideName = csvWideArtifactName(norm.stream_id);
        if (wideName && writers[wideName]) {
          const tabName = wideName.replace(/\.csv$/, "");
          const wide = buildCsvWideRowObject(tabName, norm, headersByTab);
          writers[wideName].writeRowArray(wide.values);
          const hasCsv = safeString(norm.csv || "") !== "";
          if (!hasCsv && gapCounters[norm.stream_id]) gapCounters[norm.stream_id].missing_csv += 1;
          if (hasCsv && !wide.row.csv_parse_ok && gapCounters[norm.stream_id]) gapCounters[norm.stream_id].parse_mismatch += 1;
        }
      }

      if (rowType === "EVAL" && logical.config_present === false && gapCounters[norm.stream_id]) {
        gapCounters[norm.stream_id].evals_missing_config += 1;
      }
    }

    cursor = batch.nextCursor;
  }
}

function makeStreamKeyRows(streamStats) {
  const headers = [
    "stream_id",
    "producer_id",
    "row_types_expected",
    "row_types_observed",
    "semantic_role",
    "join_key",
    "versions_seen",
    "script_ids_seen",
    "script_shas_seen",
    "notes",
  ];

  const roleMap = {
    B1M: {
      producer_id: "B1M",
      semantic_role: "Primary market-state / canonical bar-close truth stream",
      join_key: "BAR uid is the canonical bar key; joins use uid or normalized bar_uid_canonical.",
      notes: "Governed BAR_CSV_WIDE output is required for this stream when BAR rows are exported.",
    },
    B2M_AP: {
      producer_id: "B2M",
      semantic_role: "Structured momentum / parity / ML / kernel / trade-state stream",
      join_key: "bar_uid_canonical links B2M BAR/EVAL rows back to the canonical B1M bar.",
      notes: "CONFIG should preserve include_csv_in_json, sep, csv_col_count, and csv_header when present.",
    },
    B3M_PIVOTS: {
      producer_id: "B3M",
      semantic_role: "Structured pivot / boundary / nearest-level stream",
      join_key: "bar_uid_canonical links B3M BAR/EVAL rows back to the canonical B1M bar.",
      notes: "CONFIG should preserve include_csv_in_json, sep, csv_col_count, and csv_header when present.",
    },
    UNKNOWN: {
      producer_id: "UNKNOWN",
      semantic_role: "Unexpected materialized stream",
      join_key: "Unexpected stream; inspect LEDGER.csv and MANIFEST.json gaps.",
      notes: "This row appears only when materialized rows contain a non-governed stream_id.",
    },
  };

  const rows = [headers];
  const streamIds = new Set([...EXPECTED_STREAMS, ...streamStats.keys()]);
  for (const streamId of sortStrings(streamIds)) {
    const stat = streamStats.get(streamId) || {
      producerIds: new Set(),
      producerVersions: new Set(),
      scriptIds: new Set(),
      scriptShas: new Set(),
      observedRowTypes: new Set(),
    };
    const role = roleMap[streamId] || roleMap.UNKNOWN;
    rows.push([
      streamId,
      sortStrings(stat.producerIds).join(" | ") || role.producer_id,
      "CONFIG | BAR | EVAL",
      sortStrings(stat.observedRowTypes).join(" | "),
      role.semantic_role,
      role.join_key,
      sortStrings(stat.producerVersions).join(" | "),
      sortStrings(stat.scriptIds).join(" | "),
      sortStrings(stat.scriptShas).join(" | "),
      role.notes,
    ]);
  }
  return rows;
}

function buildReadmeText(context) {
  const lines = [];
  lines.push("DigitalOcean telemetry export set");
  lines.push("");
  lines.push(`Export ID: ${context.exportId}`);
  lines.push(`Exporter version: ${PACKAGE_VERSION}`);
  lines.push(`Export timestamp UTC: ${context.exportedAt.toISOString()}`);
  lines.push(`Export timestamp (${EXPORT_TIMEZONE_ID}): ${localTimestamp(context.exportedAt, EXPORT_TIMEZONE_ID)}`);
  lines.push(`Cadence: every ${EXPORT_CADENCE_MINUTES} minutes`);
  lines.push(`Drive target mode: ${GOOGLE_DRIVE_TARGET_MODE}`);
  lines.push(`Drive folder path label: ${GOOGLE_DRIVE_FOLDER_PATH_LABEL}`);
  lines.push(`Drive folder ID: ${GOOGLE_DRIVE_FOLDER_ID || "LOCAL_ONLY"}`);
  lines.push(`Latest alias enabled: ${EXPORT_LATEST_ALIAS ? "yes" : "no"}`);
  lines.push(`XLSX enabled: ${EXPORT_XLSX_ENABLED ? "yes" : "no"}`);
  lines.push(`Source watermark raw_event_id: ${context.sourceWatermark.toString()}`);
  lines.push("");
  lines.push("What each file is for:");
  lines.push("- README.txt explains the export set in plain language.");
  lines.push("- STREAM_KEY.csv names the governed streams, roles, and observed versions/build identities.");
  lines.push("- DATA_DICTIONARY.csv defines the delivered columns.");
  lines.push("- LEDGER.csv is the normalized cross-stream row ledger.");
  lines.push("- B1M/B2M/B3M *_CONFIG.csv, *_BAR.csv, and *_EVAL.csv are the stream detail artifacts.");
  lines.push("- *_BAR_CSV_WIDE.csv expands the raw BAR csv field into governed columns. Missing or unparsable csv remains visible through csv_parse_ok and csv_field_count.");
  lines.push("- MANIFEST.json is written last and lists file hashes, row counts, source watermark, observed versions, and visible gaps.");
  lines.push("");
  lines.push("Interpretation notes:");
  lines.push("- TradingView sends to DigitalOcean first.");
  lines.push("- DigitalOcean preserves raw evidence first, materializes configs/bars/evals, and then this exporter writes the file set.");
  lines.push("- Immutable timestamped run folders are the authority. The latest alias, when enabled, is only a convenience surface derived from the immutable run.");
  lines.push("- Spreadsheet-safety neutralization is applied to exported cells that begin with =, +, -, or @.");
  lines.push("");
  lines.push("Known gaps from this run:");
  if (context.knownGaps.length) {
    for (const gap of context.knownGaps) lines.push(`- ${gap}`);
  } else {
    lines.push("- No open gaps were detected by exporter-side validation for this run.");
  }
  lines.push("");
  lines.push("Retention policy:");
  lines.push("- Immutable timestamped exports are kept. No automatic deletion is performed by this exporter.");
  return lines.join("\n") + "\n";
}

function buildManifest({
  exportId,
  exportedAt,
  sourceWatermark,
  previousSuccessfulWatermark,
  artifactMetadata,
  streamStats,
  gapCounters,
  nonMaterializedCounts,
  unknownStreamCounts,
}) {
  const producerVersionSet = {};
  const scriptIdentitySet = {};
  for (const [streamId, stat] of streamStats.entries()) {
    producerVersionSet[streamId] = sortStrings(stat.producerVersions);
    scriptIdentitySet[streamId] = {
      script_ids: sortStrings(stat.scriptIds),
      script_shas: sortStrings(stat.scriptShas),
    };
  }

  const knownGaps = [];
  for (const streamId of EXPECTED_STREAMS) {
    const g = gapCounters[streamId];
    appendKnownGap(knownGaps, g.missing_csv > 0, `${streamId} has ${g.missing_csv} BAR rows with no raw csv preserved in the current export horizon.`);
    appendKnownGap(knownGaps, g.parse_mismatch > 0, `${streamId} has ${g.parse_mismatch} BAR rows whose csv field did not match the governed CSV-wide column count.`);
    appendKnownGap(knownGaps, g.bars_missing_config > 0, `${streamId} has ${g.bars_missing_config} BAR rows whose matching CONFIG row was not found by materialization at export time.`);
    appendKnownGap(knownGaps, g.evals_missing_config > 0, `${streamId} has ${g.evals_missing_config} EVAL rows whose matching CONFIG row was not found by materialization at export time.`);
  }

  const unknownEntries = Object.entries(unknownStreamCounts).filter(([, n]) => n > 0);
  for (const [streamId, n] of unknownEntries) {
    knownGaps.push(`Unexpected materialized stream ${streamId} produced ${n} rows. Those rows were kept in LEDGER.csv only.`);
  }
  for (const [rowType, n] of Object.entries(nonMaterializedCounts)) {
    if (n > 0) {
      knownGaps.push(`raw_events contains ${n} retained non-materialized ${rowType} rows at or below the export watermark. These remain evidence in DigitalOcean but are not part of the materialized artifact family.`);
    }
  }

  const artifacts = REQUIRED_ARTIFACT_ORDER.map((name) => artifactMetadata[name]).filter(Boolean);
  if (artifactMetadata["raw_request_summary.csv"]) artifacts.push(artifactMetadata["raw_request_summary.csv"]);

  const rowCountsByArtifact = {};
  for (const artifact of artifacts) rowCountsByArtifact[artifact.name] = artifact.row_count ?? 0;

  return {
    export_id: exportId,
    exporter_version: PACKAGE_VERSION,
    export_timestamp_utc: exportedAt.toISOString(),
    export_timestamp_local: localTimestamp(exportedAt, EXPORT_TIMEZONE_ID),
    chosen_cadence_minutes: EXPORT_CADENCE_MINUTES,
    drive_target_mode: GOOGLE_DRIVE_TARGET_MODE,
    drive_folder: {
      id: GOOGLE_DRIVE_FOLDER_ID || null,
      path_label: GOOGLE_DRIVE_FOLDER_PATH_LABEL,
    },
    latest_alias_enabled: EXPORT_LATEST_ALIAS,
    xlsx_enabled: EXPORT_XLSX_ENABLED,
    immutable_retention_policy: "keep immutable timestamped runs; no auto-delete until an explicit retention window is later approved",
    source_watermark: {
      materializer_last_raw_event_id: Number(sourceWatermark),
      previous_successful_source_watermark: Number(previousSuccessfulWatermark || 0n),
    },
    included_artifact_names: artifacts.map((x) => x.name),
    row_counts_by_artifact: rowCountsByArtifact,
    artifacts: artifacts.map((x) => ({
      name: x.name,
      mime_type: x.mime_type,
      sha256: x.sha256,
      size_bytes: x.size_bytes,
      row_count: x.row_count ?? 0,
    })),
    producer_version_set: producerVersionSet,
    script_identity_set: scriptIdentitySet,
    csv_wide_gap_summary: gapCounters,
    non_materialized_raw_event_counts: nonMaterializedCounts,
    unexpected_materialized_stream_counts: unknownStreamCounts,
    known_omissions_or_open_gaps: knownGaps,
    status: knownGaps.length ? "OK_WITH_VISIBLE_GAPS" : "OK",
  };
}

function fileMetaFromDisk(logicalName, filePath, mimeType, rowCount = null) {
  const body = fs.readFileSync(filePath);
  return {
    logical_name: logicalName,
    name: logicalName,
    file_path: filePath,
    mime_type: mimeType,
    sha256: sha256Hex(body),
    size_bytes: body.length,
    row_count: rowCount,
  };
}

async function maybeBuildRawRequestSummary(localDir, sourceWatermark) {
  if (!DRIVE_EXPORTER_INCLUDE_RAW_REQUEST_SUMMARY) return null;
  if (!(await tableExists("raw_requests")) || !(await tableExists("raw_events"))) return null;

  const filePath = path.join(localDir, "raw_request_summary.csv");
  const headers = [
    "request_id",
    "received_at_utc",
    "path",
    "auth_ok",
    "parse_ok",
    "payload_sha256",
    "payload_size_bytes",
    "bundle_version",
    "bundle_type",
    "sent_at_ms",
    "record_count",
  ];
  const writer = new ArtifactWriter(filePath, headers);

  let cursor = 0n;
  for (;;) {
    const rs = await dbQuery(`
      with visible_requests as (
        select distinct raw_request_id
        from raw_events
        where id <= $1 and raw_request_id is not null
      )
      select rr.id, rr.request_id, rr.received_at, rr.path, rr.auth_ok, rr.parse_ok,
             rr.payload_sha256, rr.payload_size_bytes, rr.bundle_version, rr.bundle_type,
             rr.sent_at_ms, rr.record_count
      from raw_requests rr
      join visible_requests vr on vr.raw_request_id = rr.id
      where rr.id > $2
      order by rr.id asc
      limit $3
    `, [sourceWatermark.toString(), cursor.toString(), DRIVE_EXPORTER_BATCH_SIZE]);

    if (!rs.rows.length) break;

    for (const row of rs.rows) {
      writer.writeRowObject({
        request_id: row.request_id,
        received_at_utc: toIso(row.received_at),
        path: row.path,
        auth_ok: row.auth_ok,
        parse_ok: row.parse_ok,
        payload_sha256: row.payload_sha256,
        payload_size_bytes: row.payload_size_bytes,
        bundle_version: row.bundle_version,
        bundle_type: row.bundle_type,
        sent_at_ms: row.sent_at_ms,
        record_count: row.record_count,
      });
      cursor = toBigInt(row.id);
    }
  }

  const closed = await writer.close();
  return fileMetaFromDisk("raw_request_summary.csv", filePath, "text/csv", closed.row_count);
}

async function buildArtifacts(localDir, sourceWatermark) {
  const headersByTab = loadHeaders();
  assertContractHeaders(headersByTab);
  const compatibility = await makeRawEventsCompatibilityInfo();

  const writerConfigs = {
    "LEDGER.csv": headersByTab.LEDGER,
    "B1M_CONFIG.csv": headersByTab.B1M_CONFIG,
    "B1M_BAR.csv": headersByTab.B1M_BAR,
    "B1M_EVAL.csv": headersByTab.B1M_EVAL,
    "B1M_BAR_CSV_WIDE.csv": headersByTab.B1M_BAR_CSV_WIDE,
    "B2M_CONFIG.csv": headersByTab.B2M_CONFIG,
    "B2M_BAR.csv": headersByTab.B2M_BAR,
    "B2M_EVAL.csv": headersByTab.B2M_EVAL,
    "B2M_BAR_CSV_WIDE.csv": headersByTab.B2M_BAR_CSV_WIDE,
    "B3M_CONFIG.csv": headersByTab.B3M_CONFIG,
    "B3M_BAR.csv": headersByTab.B3M_BAR,
    "B3M_EVAL.csv": headersByTab.B3M_EVAL,
    "B3M_BAR_CSV_WIDE.csv": headersByTab.B3M_BAR_CSV_WIDE,
  };

  const writers = {};
  for (const [name, headers] of Object.entries(writerConfigs)) {
    writers[name] = new ArtifactWriter(path.join(localDir, name), headers);
  }

  const streamStats = new Map();
  const gapCounters = createGapCounters();
  const unknownStreamCounts = {};

  await exportTableToArtifacts("configs", "CONFIG", sourceWatermark, compatibility, headersByTab, writers, streamStats, gapCounters, unknownStreamCounts);
  await exportTableToArtifacts("bars", "BAR", sourceWatermark, compatibility, headersByTab, writers, streamStats, gapCounters, unknownStreamCounts);
  await exportTableToArtifacts("evals", "EVAL", sourceWatermark, compatibility, headersByTab, writers, streamStats, gapCounters, unknownStreamCounts);

  const artifactMetadata = {};
  for (const [name, writer] of Object.entries(writers)) {
    const closed = await writer.close();
    artifactMetadata[name] = fileMetaFromDisk(name, path.join(localDir, name), "text/csv", closed.row_count);
  }

  const streamKeyRows = makeStreamKeyRows(streamStats);
  const streamKeyPath = path.join(localDir, "STREAM_KEY.csv");
  fs.writeFileSync(streamKeyPath, streamKeyRows.map((r) => csvLine(r)).join("\n") + "\n", "utf8");
  artifactMetadata["STREAM_KEY.csv"] = fileMetaFromDisk("STREAM_KEY.csv", streamKeyPath, "text/csv", streamKeyRows.length - 1);

  const dictionaryRows = buildDataDictionaryRows(headersByTab);
  const dictionaryPath = path.join(localDir, "DATA_DICTIONARY.csv");
  fs.writeFileSync(dictionaryPath, dictionaryRows.map((r) => csvLine(r)).join("\n") + "\n", "utf8");
  artifactMetadata["DATA_DICTIONARY.csv"] = fileMetaFromDisk("DATA_DICTIONARY.csv", dictionaryPath, "text/csv", dictionaryRows.length - 1);

  const nonMaterializedCounts = await fetchNonMaterializedCounts(sourceWatermark);
  const exportedAt = new Date();
  const exportId = path.basename(localDir);
  const manifestPreview = buildManifest({
    exportId,
    exportedAt,
    sourceWatermark,
    previousSuccessfulWatermark: 0n,
    artifactMetadata,
    streamStats,
    gapCounters,
    nonMaterializedCounts,
    unknownStreamCounts,
  });
  const readmeText = buildReadmeText({
    exportId,
    exportedAt,
    sourceWatermark,
    knownGaps: manifestPreview.known_omissions_or_open_gaps,
  });
  const readmePath = path.join(localDir, "README.txt");
  fs.writeFileSync(readmePath, readmeText, "utf8");
  artifactMetadata["README.txt"] = fileMetaFromDisk("README.txt", readmePath, "text/plain", null);

  const rawRequestSummary = await maybeBuildRawRequestSummary(localDir, sourceWatermark);
  if (rawRequestSummary) artifactMetadata[rawRequestSummary.name] = rawRequestSummary;

  return {
    artifactMetadata,
    headersByTab,
    streamStats,
    gapCounters,
    nonMaterializedCounts,
    unknownStreamCounts,
    exportedAt,
  };
}

async function getDriveClient() {
  const auth = new google.auth.OAuth2(
    GOOGLE_OAUTH_CLIENT_ID,
    GOOGLE_OAUTH_CLIENT_SECRET,
    GOOGLE_OAUTH_REDIRECT_URI
  );
  auth.setCredentials({ refresh_token: GOOGLE_OAUTH_REFRESH_TOKEN });
  await auth.getAccessToken();
  return google.drive({ version: "v3", auth });
}

async function listFoldersByName(drive, parentId, name) {
  const escaped = name.replace(/'/g, "\\'");
  const rs = await drive.files.list({
    q: [
      `mimeType = 'application/vnd.google-apps.folder'`,
      `trashed = false`,
      `'${parentId}' in parents`,
      `name = '${escaped}'`,
    ].join(" and "),
    fields: "files(id,name,createdTime)",
    orderBy: "createdTime asc",
    pageSize: 50,
  });
  return rs.data.files || [];
}

async function ensureFolder(drive, parentId, name) {
  const existing = await listFoldersByName(drive, parentId, name);
  if (existing.length) return existing[0];
  const created = await drive.files.create({
    requestBody: {
      name,
      parents: [parentId],
      mimeType: "application/vnd.google-apps.folder",
    },
    fields: "id,name",
  });
  return created.data;
}

async function renameDriveItem(drive, fileId, newName) {
  const rs = await drive.files.update({
    fileId,
    requestBody: { name: newName },
    fields: "id,name",
  });
  return rs.data;
}

async function trashDriveItem(drive, fileId) {
  await drive.files.update({
    fileId,
    requestBody: { trashed: true },
    fields: "id,trashed",
  });
}

async function uploadFileToFolder(drive, parentId, fileMeta) {
  const media = {
    mimeType: fileMeta.mime_type,
    body: fs.createReadStream(fileMeta.file_path),
  };
  const rs = await drive.files.create({
    requestBody: {
      name: fileMeta.name,
      parents: [parentId],
      mimeType: fileMeta.mime_type,
    },
    media,
    fields: "id,name,parents",
  });
  return {
    ...fileMeta,
    drive_file_id: rs.data.id,
    drive_parent_id: parentId,
  };
}

async function uploadArtifactSet(drive, folderId, artifacts) {
  const uploaded = [];
  const nonManifest = artifacts.filter((x) => x.name !== "MANIFEST.json");
  const manifest = artifacts.find((x) => x.name === "MANIFEST.json");

  for (const artifact of nonManifest) {
    uploaded.push(await uploadFileToFolder(drive, folderId, artifact));
  }
  if (manifest) uploaded.push(await uploadFileToFolder(drive, folderId, manifest));
  return uploaded;
}

async function publishToDrive(artifacts) {
  const drive = await getDriveClient();
  const runsFolder = await ensureFolder(drive, GOOGLE_DRIVE_FOLDER_ID, DRIVE_RUNS_FOLDER_NAME);
  const immutableFolder = await ensureFolder(drive, runsFolder.id, artifacts.runFolderName);
  const immutableUploaded = await uploadArtifactSet(drive, immutableFolder.id, artifacts.files);

  let latestFolderId = null;
  let latestManifestFileId = null;
  let latestUploaded = [];

  if (EXPORT_LATEST_ALIAS) {
    const stagingName = `${DRIVE_LATEST_FOLDER_NAME}__staging__${artifacts.exportId}`;
    const stagingFolder = await ensureFolder(drive, GOOGLE_DRIVE_FOLDER_ID, stagingName);
    latestUploaded = await uploadArtifactSet(drive, stagingFolder.id, artifacts.files);

    const existingLatestFolders = await listFoldersByName(drive, GOOGLE_DRIVE_FOLDER_ID, DRIVE_LATEST_FOLDER_NAME);
    for (const folder of existingLatestFolders) {
      await renameDriveItem(drive, folder.id, `${DRIVE_LATEST_FOLDER_NAME}__old__${artifacts.exportId}`);
      await trashDriveItem(drive, folder.id);
    }

    await renameDriveItem(drive, stagingFolder.id, DRIVE_LATEST_FOLDER_NAME);
    latestFolderId = stagingFolder.id;
    const latestManifest = latestUploaded.find((x) => x.name === "MANIFEST.json");
    latestManifestFileId = latestManifest?.drive_file_id || null;
  }

  const immutableManifest = immutableUploaded.find((x) => x.name === "MANIFEST.json");

  return {
    immutable_folder_id: immutableFolder.id,
    immutable_manifest_file_id: immutableManifest?.drive_file_id || null,
    latest_folder_id: latestFolderId,
    latest_manifest_file_id: latestManifestFileId,
    immutable_uploaded: immutableUploaded,
    latest_uploaded: latestUploaded,
    note: EXPORT_LATEST_ALIAS
      ? "Immutable run published; latest alias folder refreshed from staging."
      : "Immutable run published; latest alias disabled.",
  };
}

async function run() {
  await ensureExporterSchema();

  const gotLock = await acquireExporterLock();
  if (!gotLock) throw new Error("drive-exporter is already running");

  let runId = null;
  try {
    const slot = await getSlotState(DRIVE_EXPORTER_SLOT_NAME);
    await markSlotStarted(DRIVE_EXPORTER_SLOT_NAME);

    const sourceWatermark = await requireMaterializerState();
    const exportStartedAt = new Date();
    const exportId = `${toTimestampSlug(exportStartedAt)}__${crypto.randomUUID().slice(0, 8)}`;
    runId = await createRunRow(
      DRIVE_EXPORTER_SLOT_NAME,
      exportId,
      sourceWatermark,
      toBigInt(slot?.last_successful_source_watermark || 0)
    );

    const baseLocalDir = DRIVE_EXPORTER_LOCAL_OUTPUT_DIR
      ? path.resolve(DRIVE_EXPORTER_LOCAL_OUTPUT_DIR)
      : fs.mkdtempSync(path.join(os.tmpdir(), "drive-exporter-"));
    fs.mkdirSync(baseLocalDir, { recursive: true });

    const runFolderName = `run_${toTimestampSlug(exportStartedAt)}__w${sourceWatermark.toString()}__${exportId.slice(-8)}`;
    const runLocalDir = path.join(baseLocalDir, runFolderName);
    fs.mkdirSync(runLocalDir, { recursive: true });

    const built = await buildArtifacts(runLocalDir, sourceWatermark);
    const manifest = buildManifest({
      exportId,
      exportedAt: built.exportedAt,
      sourceWatermark,
      previousSuccessfulWatermark: toBigInt(slot?.last_successful_source_watermark || 0),
      artifactMetadata: built.artifactMetadata,
      streamStats: built.streamStats,
      gapCounters: built.gapCounters,
      nonMaterializedCounts: built.nonMaterializedCounts,
      unknownStreamCounts: built.unknownStreamCounts,
    });

    const manifestPath = path.join(runLocalDir, "MANIFEST.json");
    fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + "\n", "utf8");
    built.artifactMetadata["MANIFEST.json"] = fileMetaFromDisk("MANIFEST.json", manifestPath, "application/json", null);

    const orderedFiles = REQUIRED_ARTIFACT_ORDER
      .map((name) => built.artifactMetadata[name])
      .filter(Boolean);
    if (built.artifactMetadata["raw_request_summary.csv"]) {
      orderedFiles.push(built.artifactMetadata["raw_request_summary.csv"]);
    }
    orderedFiles.push(built.artifactMetadata["MANIFEST.json"]);

    let publicationSummary;
    let uploadedFiles;
    if (DRIVE_EXPORTER_SKIP_DRIVE_UPLOAD) {
      publicationSummary = {
        immutable_folder_id: null,
        immutable_manifest_file_id: null,
        latest_folder_id: null,
        latest_manifest_file_id: null,
        note: `Drive upload skipped; artifacts left on local disk at ${runLocalDir}`,
      };
      uploadedFiles = orderedFiles.map((x) => ({ ...x, phase: "local_only" }));
    } else {
      const published = await publishToDrive({
        exportId,
        runFolderName,
        files: orderedFiles,
      });
      publicationSummary = published;
      uploadedFiles = [
        ...published.immutable_uploaded.map((x) => ({ ...x, phase: "immutable" })),
        ...published.latest_uploaded.map((x) => ({ ...x, phase: "latest" })),
      ];
    }

    const byPhase = new Map();
    for (const file of uploadedFiles) {
      if (!byPhase.has(file.phase)) byPhase.set(file.phase, []);
      byPhase.get(file.phase).push(file);
    }
    for (const [phase, files] of byPhase.entries()) {
      await noteArtifactFiles(runId, phase, files);
    }

    await markRunSuccess(runId, manifest, publicationSummary, uploadedFiles);

    const counts = await fetchTableCounts(sourceWatermark);
    console.log(
      `drive-exporter finished: status=${manifest.status} watermark=${sourceWatermark.toString()} ` +
      `configs=${counts.configs} bars=${counts.bars} evals=${counts.evals} artifacts=${orderedFiles.length}`
    );
    if (DRIVE_EXPORTER_SKIP_DRIVE_UPLOAD) {
      console.log(`local artifacts path: ${runLocalDir}`);
    }
  } catch (err) {
    await markRunFailure(runId, err);
    throw err;
  } finally {
    await releaseExporterLock();
    await pool.end().catch(() => {});
  }
}

run().catch((err) => {
  console.error("FATAL", err);
  process.exit(1);
});
