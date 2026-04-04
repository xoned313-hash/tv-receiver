
import fs from "fs";
import crypto from "crypto";
import pg from "pg";
import { google } from "googleapis";

const { Pool } = pg;

const DATABASE_URL_RAW = (process.env.DATABASE_URL || "").trim();
const CA_CERT = (process.env.CA_CERT || process.env.DATABASE_CA_CERT || "").trim();
const PGSSL_INSECURE = (process.env.PGSSL_INSECURE || "").trim() === "1";
const EXPORTER_ENV = (process.env.EXPORTER_ENV || process.env.RECEIVER_ENV || "prod").trim().toLowerCase();
const GOOGLE_SPREADSHEET_ID = (process.env.GOOGLE_SPREADSHEET_ID || "").trim();
const GOOGLE_SERVICE_ACCOUNT_JSON = (process.env.GOOGLE_SERVICE_ACCOUNT_JSON || process.env.GOOGLE_SERVICE_ACCOUNT_KEY_JSON || "").trim();
const GOOGLE_SERVICE_ACCOUNT_FILE = (process.env.GOOGLE_SERVICE_ACCOUNT_FILE || "").trim();
const WORKBOOK_HEADERS_PATH = (process.env.WORKBOOK_HEADERS_PATH || "./workbook_headers.json").trim();
const EXPORTER_BATCH_SIZE = Math.max(1, parseInt(process.env.EXPORTER_BATCH_SIZE || "250", 10));
const EXPORTER_POLL_MS = Math.max(1000, parseInt(process.env.EXPORTER_POLL_MS || "5000", 10));
const EXPORTER_TAIL_RECONCILE_ROWS = Math.max(25, parseInt(process.env.EXPORTER_TAIL_RECONCILE_ROWS || "200", 10));
const ENABLE_TAIL_RECONCILE = (process.env.ENABLE_TAIL_RECONCILE || "1").trim() !== "0";
const RAW_REQUESTS_REQUIRED = (process.env.RAW_REQUESTS_REQUIRED || "0").trim() === "1";

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
if (!GOOGLE_SPREADSHEET_ID) {
  console.error("FATAL: GOOGLE_SPREADSHEET_ID is not set");
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
  h.update(typeof value === "string" ? value : String(value ?? ""));
  return h.digest("hex");
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
  if (typeof value === "boolean") return value;
  if (typeof value === "number") return value;
  if (Object.prototype.toString.call(value) === "[object Date]") return value.toISOString();
  if (typeof value === "object") return clampForCell(escapeLeadingFormulaChars(JSON.stringify(value)));
  return clampForCell(escapeLeadingFormulaChars(String(value)));
}

function safeString(value) {
  if (value === null || value === undefined) return "";
  return String(value);
}

function safeNumberOrString(value) {
  if (value === null || value === undefined || value === "") return "";
  if (typeof value === "number") return value;
  const s = String(value);
  const n = Number(s);
  return Number.isNaN(n) ? s : n;
}

function rowFromHeaders(headers, obj) {
  return headers.map((h) => sanitizeCell(obj[h]));
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

function parseCsvLine(line, expectedCount) {
  const candidates = [",", ";", "\t", "|"];
  let bestParts = parseCsvLineWithSep(line, ",");
  if (expectedCount && bestParts.length === expectedCount) return bestParts;
  for (let i = 1; i < candidates.length; i++) {
    const parts = parseCsvLineWithSep(line, candidates[i]);
    if (expectedCount && parts.length === expectedCount) return parts;
    if (parts.length > bestParts.length) bestParts = parts;
  }
  return bestParts;
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

function detailTabName(streamId, rowType) {
  if (streamId === "B1M" && rowType === "CONFIG") return "B1M_CONFIG";
  if (streamId === "B1M" && rowType === "BAR") return "B1M_BAR";
  if (streamId === "B1M" && rowType === "EVAL") return "B1M_EVAL";
  if (streamId === "B2M_AP" && rowType === "CONFIG") return "B2M_CONFIG";
  if (streamId === "B2M_AP" && rowType === "BAR") return "B2M_BAR";
  if (streamId === "B2M_AP" && rowType === "EVAL") return "B2M_EVAL";
  if (streamId === "B3M_PIVOTS" && rowType === "CONFIG") return "B3M_CONFIG";
  if (streamId === "B3M_PIVOTS" && rowType === "BAR") return "B3M_BAR";
  if (streamId === "B3M_PIVOTS" && rowType === "EVAL") return "B3M_EVAL";
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
  out.cfg_sig_sha256_local = cfgSigFull ? sha256Hex(cfgSigFull) : "";
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

function buildCsvWideRow(tabName, norm, headersByTab) {
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
  if (!csvLine) return rowFromHeaders(headers, row);
  const csvHeaders = headers.slice(11);
  const parts = parseCsvLine(csvLine, csvHeaders.length);
  row.csv_field_count = parts.length;
  row.csv_parse_ok = parts.length === csvHeaders.length;
  for (let i = 0; i < csvHeaders.length; i++) {
    row[csvHeaders[i]] = i < parts.length ? parts[i] : "";
  }
  return rowFromHeaders(headers, row);
}

function colToA1(n) {
  let x = Number(n);
  let out = "";
  while (x > 0) {
    const rem = (x - 1) % 26;
    out = String.fromCharCode(65 + rem) + out;
    x = Math.floor((x - 1) / 26);
  }
  return out || "A";
}

function loadHeaders() {
  const raw = fs.readFileSync(WORKBOOK_HEADERS_PATH, "utf8");
  return JSON.parse(raw);
}

function loadServiceAccount() {
  if (GOOGLE_SERVICE_ACCOUNT_JSON) return JSON.parse(GOOGLE_SERVICE_ACCOUNT_JSON);
  if (GOOGLE_SERVICE_ACCOUNT_FILE) return JSON.parse(fs.readFileSync(GOOGLE_SERVICE_ACCOUNT_FILE, "utf8"));
  throw new Error("GOOGLE_SERVICE_ACCOUNT_JSON or GOOGLE_SERVICE_ACCOUNT_FILE must be set");
}

async function getSheetsClient() {
  const credentials = loadServiceAccount();
  const auth = new google.auth.GoogleAuth({
    credentials,
    scopes: [
      "https://www.googleapis.com/auth/spreadsheets",
      "https://www.googleapis.com/auth/drive.file",
    ],
  });
  const client = await auth.getClient();
  return google.sheets({ version: "v4", auth: client });
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
    create table if not exists sheet_export_cursors (
      stream text primary key,
      last_seen_id bigint not null default 0,
      updated_at timestamptz not null default now()
    );
  `);
  await dbQuery(`
    create table if not exists sheet_export_rows (
      tab_name text not null,
      row_key text not null,
      row_hash text not null,
      exported_at timestamptz not null default now(),
      primary key (tab_name, row_key)
    );
  `);
  await dbQuery(`
    create table if not exists sheet_export_batches (
      id bigserial primary key,
      batch_started_at timestamptz not null default now(),
      batch_finished_at timestamptz,
      stream text not null,
      source_count integer not null default 0,
      exported_count integer not null default 0,
      status text not null default 'STARTED',
      note text
    );
  `);
}

async function getCursor(stream) {
  const rs = await dbQuery(`
    insert into sheet_export_cursors (stream, last_seen_id)
    values ($1, 0)
    on conflict (stream) do nothing;
  `, [stream]);
  const rs2 = await dbQuery("select last_seen_id from sheet_export_cursors where stream = $1", [stream]);
  return BigInt(rs2.rows[0]?.last_seen_id || 0);
}

async function setCursor(stream, lastSeenId) {
  await dbQuery(`
    insert into sheet_export_cursors (stream, last_seen_id, updated_at)
    values ($1, $2, now())
    on conflict (stream)
    do update set last_seen_id = excluded.last_seen_id, updated_at = now();
  `, [stream, String(lastSeenId)]);
}

async function rowAlreadyExported(tabName, rowKey) {
  const rs = await dbQuery(
    "select 1 from sheet_export_rows where tab_name = $1 and row_key = $2",
    [tabName, rowKey]
  );
  return rs.rowCount > 0;
}

async function noteRowsExported(items) {
  if (!items.length) return;
  const values = [];
  const params = [];
  let idx = 1;
  for (const item of items) {
    values.push(`($${idx++}, $${idx++}, $${idx++}, now())`);
    params.push(item.tabName, item.rowKey, item.rowHash);
  }
  await dbQuery(`
    insert into sheet_export_rows (tab_name, row_key, row_hash, exported_at)
    values ${values.join(",\n")}
    on conflict (tab_name, row_key) do nothing;
  `, params);
}

function buildRowKeyFromHeaders(headers, row) {
  const idxReq = headers.indexOf("request_id");
  const idxRec = headers.indexOf("record_index");
  const idxUid = headers.indexOf("uid");
  const idxStream = headers.indexOf("stream_id");

  const req = idxReq >= 0 ? safeString(row[idxReq]) : "";
  const rec = idxRec >= 0 ? safeString(row[idxRec]) : "";
  const uid = idxUid >= 0 ? safeString(row[idxUid]) : "";
  const stream = idxStream >= 0 ? safeString(row[idxStream]) : "";

  if (req && rec && uid) return `${req}|${rec}|${uid}`;
  if (req && rec) return `${req}|${rec}`;
  if (req) return req;
  if (uid) return `${stream}|${uid}`;
  return sha256Hex(JSON.stringify(row));
}

async function reconcileTail(sheetsApi, headersByTab, tabName) {
  if (!ENABLE_TAIL_RECONCILE) return;
  const headers = headersByTab[tabName];
  const range = `${tabName}!A1:${colToA1(headers.length)}`;
  const resp = await sheetsApi.spreadsheets.values.get({
    spreadsheetId: GOOGLE_SPREADSHEET_ID,
    range,
    majorDimension: "ROWS",
  });
  const values = resp.data.values || [];
  if (values.length <= 1) return;
  const tail = values.slice(Math.max(1, values.length - EXPORTER_TAIL_RECONCILE_ROWS));
  const rows = [];
  for (const row of tail) {
    const normalized = headers.map((_, i) => (i < row.length ? row[i] : ""));
    rows.push({
      tabName,
      rowKey: buildRowKeyFromHeaders(headers, normalized),
      rowHash: sha256Hex(JSON.stringify(normalized)),
    });
  }
  await noteRowsExported(rows);
}

async function ensureWorkbookSheets(sheetsApi, headersByTab) {
  const meta = await sheetsApi.spreadsheets.get({
    spreadsheetId: GOOGLE_SPREADSHEET_ID,
    fields: "sheets(properties(sheetId,title))",
  });
  const existingTitles = new Set((meta.data.sheets || []).map((s) => s.properties?.title).filter(Boolean));
  const addRequests = [];
  for (const tabName of Object.keys(headersByTab)) {
    if (!existingTitles.has(tabName)) {
      addRequests.push({ addSheet: { properties: { title: tabName } } });
    }
  }
  if (addRequests.length) {
    await sheetsApi.spreadsheets.batchUpdate({
      spreadsheetId: GOOGLE_SPREADSHEET_ID,
      requestBody: { requests: addRequests },
    });
  }

  for (const [tabName, headers] of Object.entries(headersByTab)) {
    const range = `${tabName}!A1:${colToA1(headers.length)}1`;
    const resp = await sheetsApi.spreadsheets.values.get({
      spreadsheetId: GOOGLE_SPREADSHEET_ID,
      range,
      majorDimension: "ROWS",
    });
    const current = (resp.data.values && resp.data.values[0]) ? resp.data.values[0] : [];
    const isEmpty = current.length === 0 || current.every((x) => !String(x || "").trim());
    const isExact = current.length === headers.length && current.every((x, i) => String(x || "") === headers[i]);
    if (isExact) continue;
    if (!isEmpty) {
      throw new Error(`Header mismatch on ${tabName}. Refusing to overwrite governed header row.`);
    }
    await sheetsApi.spreadsheets.values.update({
      spreadsheetId: GOOGLE_SPREADSHEET_ID,
      range,
      valueInputOption: "RAW",
      requestBody: { values: [headers] },
    });
  }
}

async function fetchRawRequestsBatch(lastSeenId, batchSize) {
  if (!(await tableExists("raw_requests"))) {
    if (RAW_REQUESTS_REQUIRED) throw new Error("raw_requests table is missing");
    return { rows: [], lastSeenId };
  }
  const rs = await dbQuery(`
    select id, request_id, received_at, payload_sha256, payload_size_bytes, parse_ok,
           bundle_version, bundle_type, sent_at_ms, record_count, raw_body
    from raw_requests
    where id > $1
    order by id asc
    limit $2
  `, [String(lastSeenId), batchSize]);
  const rows = rs.rows || [];
  const newLast = rows.length ? BigInt(rows[rows.length - 1].id) : lastSeenId;
  return { rows, lastSeenId: newLast };
}

async function fetchRawEventsBatch(lastSeenId, batchSize) {
  const cols = await tableColumns("raw_events");
  const hasRecordIndex = cols.has("record_index");
  const hasPath = cols.has("path");
  const recordIndexExpr = hasRecordIndex ? "record_index" : "null::integer as record_index";
  const pathExpr = hasPath ? "path" : "null::text as path";
  const rs = await dbQuery(`
    select id, request_id, received_at, row_type, payload, ${recordIndexExpr}, ${pathExpr}
    from raw_events
    where id > $1
    order by id asc
    limit $2
  `, [String(lastSeenId), batchSize]);
  const rows = rs.rows || [];
  const newLast = rows.length ? BigInt(rows[rows.length - 1].id) : lastSeenId;
  return { rows, lastSeenId: newLast, hasRecordIndex };
}

function buildRawEnvelopeSheetRow(rawRequest, headersByTab) {
  const row = {
    request_id: safeString(rawRequest.request_id || ""),
    ingest_ts_utc: rawRequest.received_at instanceof Date ? rawRequest.received_at.toISOString() : safeString(rawRequest.received_at || ""),
    payload_sha256: safeString(rawRequest.payload_sha256 || ""),
    payload_size_bytes: safeNumberOrString(rawRequest.payload_size_bytes),
    parse_ok: Boolean(rawRequest.parse_ok),
    bundle_version: safeNumberOrString(rawRequest.bundle_version),
    bundle_type: safeString(rawRequest.bundle_type || ""),
    sent_at_ms: safeNumberOrString(rawRequest.sent_at_ms),
    record_count: safeNumberOrString(rawRequest.record_count),
    raw_body: clampForCell(rawRequest.raw_body || ""),
  };
  return rowFromHeaders(headersByTab.RAW_ENVELOPES, row);
}

function buildLedgerSheetRow(norm, headersByTab) {
  return rowFromHeaders(headersByTab.LEDGER, norm);
}

function buildDetailSheetRow(tabName, norm, headersByTab) {
  return rowFromHeaders(headersByTab[tabName], norm);
}

function recordIndexFromRow(rawEvent, syntheticByRequest) {
  if (rawEvent.record_index !== null && rawEvent.record_index !== undefined) {
    return Number(rawEvent.record_index);
  }
  const key = safeString(rawEvent.request_id || "__UNKNOWN_REQUEST__");
  const next = syntheticByRequest.get(key) || 0;
  syntheticByRequest.set(key, next + 1);
  return next;
}

async function appendRowsToSheet(sheetsApi, tabName, rows, headersByTab) {
  if (!rows.length) return;
  await sheetsApi.spreadsheets.values.append({
    spreadsheetId: GOOGLE_SPREADSHEET_ID,
    range: `${tabName}!A:${colToA1(headersByTab[tabName].length)}`,
    valueInputOption: "RAW",
    insertDataOption: "INSERT_ROWS",
    requestBody: { values: rows },
  });
}

async function exportRawRequestsBatch(sheetsApi, headersByTab) {
  const cursorName = "raw_requests";
  const lastSeen = await getCursor(cursorName);
  const batch = await fetchRawRequestsBatch(lastSeen, EXPORTER_BATCH_SIZE);
  if (!batch.rows.length) return { processed: 0 };

  await reconcileTail(sheetsApi, headersByTab, "RAW_ENVELOPES");

  const sheetRows = [];
  const ledgerRows = [];
  for (const row of batch.rows) {
    const sheetRow = buildRawEnvelopeSheetRow(row, headersByTab);
    const rowKey = safeString(row.request_id || row.id);
    if (await rowAlreadyExported("RAW_ENVELOPES", rowKey)) continue;
    sheetRows.push(sheetRow);
    ledgerRows.push({
      tabName: "RAW_ENVELOPES",
      rowKey,
      rowHash: sha256Hex(JSON.stringify(sheetRow)),
    });
  }

  if (sheetRows.length) {
    await appendRowsToSheet(sheetsApi, "RAW_ENVELOPES", sheetRows, headersByTab);
    await noteRowsExported(ledgerRows);
  }
  await setCursor(cursorName, batch.lastSeenId);
  return { processed: batch.rows.length, exported: sheetRows.length };
}

async function exportRawEventsBatch(sheetsApi, headersByTab) {
  const cursorName = "raw_events";
  const lastSeen = await getCursor(cursorName);
  const batch = await fetchRawEventsBatch(lastSeen, EXPORTER_BATCH_SIZE);
  if (!batch.rows.length) return { processed: 0 };

  const tabsToRows = new Map();
  const tabsToLedger = new Map();
  const syntheticByRequest = new Map();

  for (const rawEvent of batch.rows) {
    const payload = rawEvent.payload && typeof rawEvent.payload === "object" ? rawEvent.payload : (() => {
      try {
        return JSON.parse(rawEvent.payload || "{}");
      } catch {
        return {};
      }
    })();

    const requestId = safeString(rawEvent.request_id || payload.request_id || rawEvent.id);
    const recordIndex = recordIndexFromRow(rawEvent, syntheticByRequest);
    const ingestTs = rawEvent.received_at instanceof Date ? rawEvent.received_at.toISOString() : safeString(rawEvent.received_at || "");
    const norm = normalizeRecord(payload, requestId, recordIndex, ingestTs);
    if (!norm.uid) continue;

    const ledgerRow = buildLedgerSheetRow(norm, headersByTab);
    const ledgerKey = `${requestId}|${recordIndex}|${norm.uid}`;
    if (!tabsToRows.has("LEDGER")) tabsToRows.set("LEDGER", []);
    if (!tabsToLedger.has("LEDGER")) tabsToLedger.set("LEDGER", []);
    tabsToRows.get("LEDGER").push({ row: ledgerRow, rowKey: ledgerKey });
    tabsToLedger.get("LEDGER").push({ tabName: "LEDGER", rowKey: ledgerKey, rowHash: sha256Hex(JSON.stringify(ledgerRow)) });

    const detailTab = detailTabName(norm.stream_id, norm.row_type);
    if (detailTab && headersByTab[detailTab]) {
      const detailRow = buildDetailSheetRow(detailTab, norm, headersByTab);
      if (!tabsToRows.has(detailTab)) tabsToRows.set(detailTab, []);
      if (!tabsToLedger.has(detailTab)) tabsToLedger.set(detailTab, []);
      tabsToRows.get(detailTab).push({ row: detailRow, rowKey: ledgerKey });
      tabsToLedger.get(detailTab).push({ tabName: detailTab, rowKey: ledgerKey, rowHash: sha256Hex(JSON.stringify(detailRow)) });
    }

    if (norm.row_type === "BAR" && safeString(norm.csv || "")) {
      let csvTab = "";
      if (norm.stream_id === "B1M") csvTab = "B1M_BAR_CSV_WIDE";
      if (norm.stream_id === "B2M_AP") csvTab = "B2M_BAR_CSV_WIDE";
      if (norm.stream_id === "B3M_PIVOTS") csvTab = "B3M_BAR_CSV_WIDE";
      if (csvTab && headersByTab[csvTab]) {
        const wideRow = buildCsvWideRow(csvTab, norm, headersByTab);
        if (!tabsToRows.has(csvTab)) tabsToRows.set(csvTab, []);
        if (!tabsToLedger.has(csvTab)) tabsToLedger.set(csvTab, []);
        tabsToRows.get(csvTab).push({ row: wideRow, rowKey: ledgerKey });
        tabsToLedger.get(csvTab).push({ tabName: csvTab, rowKey: ledgerKey, rowHash: sha256Hex(JSON.stringify(wideRow)) });
      }
    }
  }

  let exportedTotal = 0;
  for (const [tabName, items] of tabsToRows.entries()) {
    if (!items.length) continue;
    await reconcileTail(sheetsApi, headersByTab, tabName);
    const rowsToAppend = [];
    const ledgerToNote = [];
    for (let i = 0; i < items.length; i++) {
      const { row, rowKey } = items[i];
      if (await rowAlreadyExported(tabName, rowKey)) continue;
      rowsToAppend.push(row);
      ledgerToNote.push(tabsToLedger.get(tabName)[i]);
    }
    if (!rowsToAppend.length) continue;
    await appendRowsToSheet(sheetsApi, tabName, rowsToAppend, headersByTab);
    await noteRowsExported(ledgerToNote);
    exportedTotal += rowsToAppend.length;
  }

  await setCursor(cursorName, batch.lastSeenId);
  return { processed: batch.rows.length, exported: exportedTotal };
}

async function runOnce(sheetsApi, headersByTab) {
  const batchMeta = await dbQuery(`
    insert into sheet_export_batches (stream, status)
    values ('EXPORTER', 'STARTED')
    returning id
  `);
  const batchId = batchMeta.rows[0].id;
  try {
    const rawReqs = await exportRawRequestsBatch(sheetsApi, headersByTab);
    const rawEvents = await exportRawEventsBatch(sheetsApi, headersByTab);
    const sourceCount = (rawReqs.processed || 0) + (rawEvents.processed || 0);
    const exportedCount = (rawReqs.exported || 0) + (rawEvents.exported || 0);
    await dbQuery(`
      update sheet_export_batches
      set batch_finished_at = now(), source_count = $2, exported_count = $3, status = 'OK', note = $4
      where id = $1
    `, [batchId, sourceCount, exportedCount, JSON.stringify({ rawReqs, rawEvents })]);
    return { sourceCount, exportedCount };
  } catch (err) {
    await dbQuery(`
      update sheet_export_batches
      set batch_finished_at = now(), status = 'ERROR', note = $2
      where id = $1
    `, [batchId, `${err.name}: ${err.message}`]);
    throw err;
  }
}

async function main() {
  const headersByTab = loadHeaders();
  await ensureExporterSchema();
  const sheetsApi = await getSheetsClient();
  await ensureWorkbookSheets(sheetsApi, headersByTab);

  console.log("gsheet-exporter ready");
  for (;;) {
    try {
      const result = await runOnce(sheetsApi, headersByTab);
      if (result.sourceCount > 0 || result.exportedCount > 0) {
        console.log(`export cycle: source=${result.sourceCount} exported=${result.exportedCount}`);
      }
    } catch (err) {
      console.error("export cycle failed", err);
    }
    await new Promise((resolve) => setTimeout(resolve, EXPORTER_POLL_MS));
  }
}

main().catch((err) => {
  console.error("FATAL", err);
  process.exit(1);
});
