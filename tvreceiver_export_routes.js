import express from "express";

const DEFAULT_LIMIT = 5000;
const DEFAULT_MAX_LIMIT = 50000;

const EXPORT_DEFS = {
  bars: {
    table: "bars",
    defaultExclude: new Set(["payload"]),
    defaultOrder: "desc",
    timeExpr: "coalesce(t_close_ms, t_subject_ms, t_event_ms, t_received_ms)",
    filters: [
      "uid",
      "request_id",
      "symbol",
      "symbol_native",
      "tf",
      "stream_id",
      "run_id",
      "event_type",
      "exchange",
      "tickerid",
      "source_family",
      "symbol_role",
      "asset_class",
      "research_cluster",
      "underlying_code",
      "quote_code",
      "instrument_type",
      "cfg_sig_sha256",
      "cfg_sig_raw",
      "cfg_sig_full",
      "config_present",
      "config_missing_reason",
    ],
    orderBy: {
      desc: "order by t_close_ms desc nulls last, received_at desc, raw_event_id desc, uid desc",
      asc: "order by t_close_ms asc nulls first, received_at asc, raw_event_id asc, uid asc",
    },
  },
  evals: {
    table: "evals",
    defaultExclude: new Set(["payload"]),
    defaultOrder: "desc",
    timeExpr: "coalesce(t_eval_close_ms, t_subject_ms, t_event_ms)",
    filters: [
      "uid",
      "parent_uid",
      "request_id",
      "symbol",
      "symbol_native",
      "tf",
      "stream_id",
      "run_id",
      "event_type",
      "exchange",
      "tickerid",
      "source_family",
      "symbol_role",
      "asset_class",
      "research_cluster",
      "underlying_code",
      "quote_code",
      "instrument_type",
      "cfg_sig_sha256",
      "cfg_sig_raw",
      "cfg_sig_full",
      "config_present",
      "config_missing_reason",
      "W",
    ],
    orderBy: {
      desc: "order by t_eval_close_ms desc nulls last, received_at desc, raw_event_id desc, uid desc",
      asc: "order by t_eval_close_ms asc nulls first, received_at asc, raw_event_id asc, uid asc",
    },
  },
  configs: {
    table: "configs",
    defaultExclude: new Set(["payload"]),
    defaultOrder: "desc",
    timeExpr: "coalesce(t_event_ms, t_subject_ms)",
    filters: [
      "uid",
      "request_id",
      "symbol",
      "symbol_native",
      "tf",
      "stream_id",
      "run_id",
      "exchange",
      "tickerid",
      "source_family",
      "symbol_role",
      "asset_class",
      "research_cluster",
      "underlying_code",
      "quote_code",
      "instrument_type",
      "cfg_sig_sha256",
      "cfg_sig_raw",
      "cfg_sig_full",
      "emit_reason",
      "exp_id",
    ],
    orderBy: {
      desc: "order by t_event_ms desc nulls last, received_at desc, raw_event_id desc, uid desc",
      asc: "order by t_event_ms asc nulls first, received_at asc, raw_event_id asc, uid asc",
    },
  },
  raw_events: {
    table: "raw_events",
    defaultExclude: new Set(["payload", "payload_raw_redacted"]),
    defaultOrder: "desc",
    timeExpr: "coalesce(t_received_ms, bundle_sent_at_ms, t_event_ms, t_subject_ms, (extract(epoch from received_at) * 1000)::bigint)",
    filters: [
      "id",
      "request_id",
      "row_type",
      "uid",
      "parent_uid",
      "symbol",
      "symbol_native",
      "tf",
      "stream_id",
      "run_id",
      "event_type",
      "exchange",
      "tickerid",
      "cfg_sig_sha256",
      "cfg_sig_raw",
      "cfg_sig_full",
      "deployment_id",
      "env",
      "producer",
      "producer_id",
      "path",
      "auth_ok",
      "parse_ok",
      "schema_match_ok",
    ],
    orderBy: {
      desc: "order by received_at desc, id desc",
      asc: "order by received_at asc, id asc",
    },
  },
};

function isObject(x) {
  return x !== null && typeof x === "object" && !Array.isArray(x);
}

function sqlIdent(name) {
  return `"${String(name).replace(/"/g, '""')}"`;
}

function asInt(value, fallback, min, max) {
  const n = Number.parseInt(String(value ?? ""), 10);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(Math.max(n, min), max);
}

function asBigIntString(value) {
  if (value == null || value === "") return null;
  const s = String(value).trim();
  if (!/^-?\d+$/.test(s)) return null;
  return s;
}

function asBool(value, fallback = false) {
  if (value == null || value === "") return fallback;
  const s = String(value).trim().toLowerCase();
  if (["1", "true", "yes", "y", "on"].includes(s)) return true;
  if (["0", "false", "no", "n", "off"].includes(s)) return false;
  return fallback;
}

function splitList(value) {
  if (value == null || value === "") return [];
  if (Array.isArray(value)) {
    return value
      .flatMap((part) => String(part).split(","))
      .map((part) => part.trim())
      .filter(Boolean);
  }
  return String(value)
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean);
}

function sanitizeFilePart(value) {
  return String(value)
    .replace(/[^A-Za-z0-9._-]+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 80);
}

function makeTimestampStamp(date = new Date()) {
  return date.toISOString().replace(/[:]/g, "").replace(/\.\d{3}Z$/, "Z");
}

function encodeCsvCell(value) {
  if (value == null) return "";

  let out = value;
  if (out instanceof Date) {
    out = out.toISOString();
  } else if (Buffer.isBuffer(out)) {
    out = out.toString("base64");
  } else if (isObject(out) || Array.isArray(out)) {
    out = JSON.stringify(out);
  } else {
    out = String(out);
  }

  if (/"|,|\n|\r/.test(out)) {
    return `"${out.replace(/"/g, '""')}"`;
  }
  return out;
}

function rowsToCsv(columns, rows) {
  const header = columns.map(encodeCsvCell).join(",");
  const body = rows.map((row) => columns.map((col) => encodeCsvCell(row[col])).join(",")).join("\n");
  return body ? `${header}\n${body}\n` : `${header}\n`;
}

async function getColumns(pool, tableName) {
  const rs = await pool.query(
    `
      select column_name, data_type
      from information_schema.columns
      where table_schema = 'public'
        and table_name = $1
      order by ordinal_position
    `,
    [tableName]
  );

  return rs.rows.map((r) => ({
    name: String(r.column_name),
    dataType: String(r.data_type || ""),
  }));
}

function buildRawEventsVirtuals(available) {
  const hasPayload = available.has("payload");
  const hasPayloadRawRedacted = available.has("payload_raw_redacted");
  if (hasPayload && hasPayloadRawRedacted) {
    return {
      payload_preview: "left(coalesce(payload::text, payload_raw_redacted::text, ''), 2000)",
    };
  }
  if (hasPayload) {
    return {
      payload_preview: "left(coalesce(payload::text, ''), 2000)",
    };
  }
  if (hasPayloadRawRedacted) {
    return {
      payload_preview: "left(coalesce(payload_raw_redacted::text, ''), 2000)",
    };
  }
  return {};
}

function pickColumns({ kind, requested, includePayload, actualColumns }) {
  const actualSet = new Set(actualColumns.map((c) => c.name));
  const virtuals = kind === "raw_events" ? buildRawEventsVirtuals(actualSet) : {};
  const virtualNames = Object.keys(virtuals);
  const requestedList = splitList(requested);

  if (requestedList.length > 0) {
    const selected = requestedList.filter((name) => actualSet.has(name) || Object.hasOwn(virtuals, name));
    const withPayload = includePayload
      ? selected
      : selected.filter((name) => name !== "payload" && name !== "payload_raw_redacted");
    return { columns: withPayload, virtuals };
  }

  const def = EXPORT_DEFS[kind];
  let names = actualColumns.map((c) => c.name).filter((name) => !def.defaultExclude.has(name));

  if (includePayload) {
    for (const maybe of ["payload", "payload_raw_redacted"]) {
      if (actualSet.has(maybe) && !names.includes(maybe)) names.push(maybe);
    }
  }

  if (kind === "raw_events" && virtualNames.length > 0 && !names.includes("payload_preview")) {
    names.push("payload_preview");
  }

  return { columns: names, virtuals };
}

function parseExportOptions(req) {
  const q = req.query || {};
  return {
    limit: asInt(q.limit, DEFAULT_LIMIT, 1, DEFAULT_MAX_LIMIT),
    order: String(q.order || "desc").trim().toLowerCase() === "asc" ? "asc" : "desc",
    fromMs: asBigIntString(q.from_ms),
    toMs: asBigIntString(q.to_ms),
    includePayload: asBool(q.include_payload, false),
    columns: q.columns,
  };
}

function appendListFilter({ where, values, idxRef, available, column, queryValue, cast = "text[]" }) {
  if (!available.has(column)) return;
  const list = splitList(queryValue);
  if (list.length === 0) return;
  where.push(`${sqlIdent(column)} = any($${idxRef.value}::${cast})`);
  values.push(list);
  idxRef.value += 1;
}

function appendScalarFilter({ where, values, idxRef, available, column, queryValue, cast }) {
  if (!available.has(column)) return;
  if (queryValue == null || queryValue === "") return;
  where.push(`${sqlIdent(column)} = $${idxRef.value}${cast ? `::${cast}` : ""}`);
  values.push(queryValue);
  idxRef.value += 1;
}

function appendTimeFilters({ where, values, idxRef, timeExpr, fromMs, toMs }) {
  if (fromMs != null) {
    where.push(`${timeExpr} >= $${idxRef.value}::bigint`);
    values.push(fromMs);
    idxRef.value += 1;
  }
  if (toMs != null) {
    where.push(`${timeExpr} <= $${idxRef.value}::bigint`);
    values.push(toMs);
    idxRef.value += 1;
  }
}

function buildQuery({ kind, selectedColumns, virtuals, availableColumns, options, req }) {
  const def = EXPORT_DEFS[kind];
  const available = new Set(availableColumns.map((c) => c.name));
  const values = [];
  const where = [];
  const idxRef = { value: 1 };

  for (const column of def.filters) {
    const queryValue = req.query?.[column];
    if (queryValue == null || queryValue === "") continue;

    if (column === "id" || column === "W") {
      appendScalarFilter({
        where,
        values,
        idxRef,
        available,
        column,
        queryValue: asBigIntString(queryValue),
        cast: column === "W" ? "integer" : "bigint",
      });
    } else if (["auth_ok", "parse_ok", "schema_match_ok", "config_present"].includes(column)) {
      appendScalarFilter({
        where,
        values,
        idxRef,
        available,
        column,
        queryValue: asBool(queryValue, false),
        cast: "boolean",
      });
    } else {
      appendListFilter({
        where,
        values,
        idxRef,
        available,
        column,
        queryValue,
      });
    }
  }

  appendTimeFilters({
    where,
    values,
    idxRef,
    timeExpr: def.timeExpr,
    fromMs: options.fromMs,
    toMs: options.toMs,
  });

  const selectSql = selectedColumns
    .map((name) => {
      if (Object.hasOwn(virtuals, name)) return `${virtuals[name]} as ${sqlIdent(name)}`;
      return sqlIdent(name);
    })
    .join(",\n        ");

  const sql = `
    select
      ${selectSql}
    from ${sqlIdent(def.table)}
    ${where.length > 0 ? `where ${where.join(" and ")}` : ""}
    ${def.orderBy[options.order] || def.orderBy[def.defaultOrder]}
    limit $${idxRef.value}
  `;

  values.push(options.limit);
  return { sql, values };
}

function defaultFilename(kind, req) {
  const pieces = [kind];
  for (const key of ["symbol", "stream_id", "run_id", "tf"]) {
    const list = splitList(req.query?.[key]);
    if (list.length === 1) pieces.push(sanitizeFilePart(list[0]));
  }
  pieces.push(makeTimestampStamp());
  return `${pieces.filter(Boolean).join("_")}.csv`;
}

function makeDocs(reqBase) {
  return {
    ok: true,
    routes: {
      bars: `${reqBase}/bars.csv?secret=YOUR_SECRET`,
      evals: `${reqBase}/evals.csv?secret=YOUR_SECRET`,
      configs: `${reqBase}/configs.csv?secret=YOUR_SECRET`,
      raw_events: `${reqBase}/raw_events.csv?secret=YOUR_SECRET`,
    },
    common_params: {
      secret: "required",
      limit: `default ${DEFAULT_LIMIT}, max ${DEFAULT_MAX_LIMIT}`,
      order: "asc | desc",
      from_ms: "inclusive lower bound on the table's main event time",
      to_ms: "inclusive upper bound on the table's main event time",
      include_payload: "0 | 1",
      columns: "comma-separated explicit column list",
      symbol: "comma-separated symbols",
      tf: "comma-separated timeframes",
      stream_id: "comma-separated stream ids",
      run_id: "comma-separated run ids",
      request_id: "comma-separated request ids",
      uid: "comma-separated uids",
    },
  };
}

export function installExportRoutes({
  app,
  pool,
  webhookSecret,
  basePath = "/export",
  defaultLimit = DEFAULT_LIMIT,
  maxLimit = DEFAULT_MAX_LIMIT,
} = {}) {
  if (!app) throw new Error("installExportRoutes requires { app }");
  if (!pool) throw new Error("installExportRoutes requires { pool }");

  const secret = String(webhookSecret ?? process.env.WEBHOOK_SECRET ?? "").trim();
  if (!secret) throw new Error("installExportRoutes requires webhookSecret (fail-closed)");

  const router = express.Router();
  const normalizedBase = basePath.endsWith("/") ? basePath.slice(0, -1) : basePath;

  const requireSecret = (req, res, next) => {
    if (String(req.query?.secret || "") !== secret) {
      return res.status(401).json({ ok: false, error: "unauthorized" });
    }
    return next();
  };

  router.get(normalizedBase, requireSecret, async (req, res) => {
    res.json(makeDocs(normalizedBase));
  });


  router.get(`${normalizedBase}/:kind/schema`, requireSecret, async (req, res) => {
    const kind = String(req.params.kind || "").trim().toLowerCase();
    const def = EXPORT_DEFS[kind];
    if (!def) {
      return res.status(404).json({ ok: false, error: "unknown_export_kind" });
    }

    try {
      const actualColumns = await getColumns(pool, def.table);
      const available = new Set(actualColumns.map((c) => c.name));
      const virtuals = kind === "raw_events" ? buildRawEventsVirtuals(available) : {};
      return res.json({
        ok: true,
        kind,
        table: def.table,
        columns: actualColumns,
        virtual_columns: Object.keys(virtuals),
      });
    } catch (e) {
      return res.status(500).json({ ok: false, error: { message: e.message, code: e.code || null } });
    }
  });

  router.get(`${normalizedBase}/:kind.csv`, requireSecret, async (req, res) => {
    const kind = String(req.params.kind || "").trim().toLowerCase();
    const def = EXPORT_DEFS[kind];
    if (!def) {
      return res.status(404).json({ ok: false, error: "unknown_export_kind" });
    }

    try {
      const options = parseExportOptions(req);
      options.limit = asInt(req.query?.limit, defaultLimit, 1, maxLimit);

      const actualColumns = await getColumns(pool, def.table);
      if (actualColumns.length === 0) {
        return res.status(404).json({ ok: false, error: "table_not_found_or_no_columns" });
      }

      const { columns: selectedColumns, virtuals } = pickColumns({
        kind,
        requested: options.columns,
        includePayload: options.includePayload,
        actualColumns,
      });

      if (selectedColumns.length === 0) {
        return res.status(400).json({ ok: false, error: "no_exportable_columns_selected" });
      }

      const { sql, values } = buildQuery({
        kind,
        selectedColumns,
        virtuals,
        availableColumns: actualColumns,
        options,
        req,
      });

      const rs = await pool.query(sql, values);
      const csv = rowsToCsv(selectedColumns, rs.rows);
      const filename = defaultFilename(kind, req);

      res.setHeader("Content-Type", "text/csv; charset=utf-8");
      res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
      res.setHeader("Cache-Control", "no-store");
      return res.status(200).send(csv);
    } catch (e) {
      return res.status(500).json({ ok: false, error: { message: e.message, code: e.code || null } });
    }
  });

  app.use(router);
  return router;
}

export default installExportRoutes;
