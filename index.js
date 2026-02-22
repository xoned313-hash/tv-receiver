import express from "express";
import pg from "pg";

const { Pool } = pg;

const app = express();

// TradingView often sends text/plain. Accept everything as text.
app.use(express.text({ type: "*/*", limit: "2mb" }));

const PORT = parseInt(process.env.PORT || "8080", 10);

const WEBHOOK_SECRET = (process.env.WEBHOOK_SECRET || "").trim();
const DATABASE_URL_RAW = (process.env.DATABASE_URL || "").trim();

// DigitalOcean DB component commonly provides CA cert via ${<db>.CA_CERT}
const CA_CERT = (process.env.CA_CERT || process.env.DATABASE_CA_CERT || "").trim();

// Set PGSSL_INSECURE=1 ONLY if you want a temporary insecure bypass.
const PGSSL_INSECURE = (process.env.PGSSL_INSECURE || "").trim() === "1";

function scrubDbUrl(url) {
  if (!url) return "";
  try {
    const u = new URL(url);
    // IMPORTANT: node-postgres can override ssl config when sslmode is present.
    u.searchParams.delete("sslmode");
    return u.toString();
  } catch {
    // Fallback: strip sslmode manually
    return url.replace(/[?&]sslmode=[^&]+/i, "");
  }
}

function pgSslConfig() {
  const pgsslmode = (process.env.PGSSLMODE || "").toLowerCase();

  if (pgsslmode === "disable") return false;

  // Recommended secure path: verify using CA cert
  if (CA_CERT) {
    retu [oai_citation:22‡GITHUB REPOSITORY .txt](sediment://file_00000000ddb471f887bca608eeb8e083)horized: true,
      ca: CA_CERT.replace(/\\n/g, "\n"),
    };
  }

  // Optional insecure bypass (only if you explicitly set it)
  if (PGSSL_INSECURE) {
    return { rejectUnauthorized: false };
  }

  // Fail closed by default (forces you to set CA_CERT correctly)
  return { rejectUnauthorized: true };
}

const pool = new Pool({
  connectionString: scrubDbUrl(DATABASE_URL_RAW),
  ssl: pgSslConfig(),
  max: 5,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 10_000,
});

async function ensureSchema() {
  await pool.query(`
    create table if not exists raw_events (
      id bigserial primary key,
      received_at timestamptz not null default now(),
      path text not null,
      source_ip text,
      user_agent text,
      payload jsonb not null
    );
  `);

  await pool.query(`
    create index if not exists raw_events_received_at_idx
    on raw_events (received_at desc);
  `);
}

function requireSecret(req, res) {
  if (!WEBHOOK_SECRET) {
    res.status(500).json({
      ok: false,
      error: "server_misconfigured",
      detail: "WEBHOOK_SECRET is not set",
    });
    return false;
  }

  const provided = String(req.query.secret || "");
  if (provided !== WEBHOOK_SECRET) {
    res.status(401).json({ ok: false, error: "unauthorized" });
    return false;
  }
  return true;
}

function parsePayload(req) {
  const raw = (req.body ?? "").trim();
  if (!raw) return { _parse_ok: false, _error: "empty_body" };

  try {
    return JSON.parse(raw);
  } catch {
    return {
      _parse_ok: false,
      _error: "json_parse_failed",
      _raw: raw.slice(0, 5000),
    };
  }
}

function getSourceIp(req) {
  const xf = (req.headers["x-forwarded-for"] || "").toString();
  if (xf) return xf.split(",")[0].trim();
  return req.socket?.remoteAddress || null;
}

app.get("/", (req, res) => {
  res.status(200).send("ok");
});

// Health endpoint: this is what you open in the browser.
app.get("/healthz", async (req, res) => {
  const now = new Date().toISOString();
  try {
    await pool.query("select 1 as ok");
    const c = await pool.query("select count(*)::bigint as n from raw_events");

    res.json({
      ok: true,
      now,
      db_ok: true,
      raw_events_count: c.rows[0].n,
      tls: {
        ca_cert_configured: Boolean(CA_CERT),
        insecure_allowed: PGSSL_INSECURE,
      },
    });
  } catch (e) {
    res.status(500).json({
      ok: false,
      now,
      db_ok: false,
      error: { message: e.message, code: e.code },
      tls: {
        ca_cert_configured: Boolean(CA_CERT),
        insecure_allowed: PGSSL_INSECURE,
      },
    });
  }
});

async function handleWebhook(req, res) {
  if (!requireSecret(req, res)) return;

  const payload = parsePayload(req);

  // B1M_TRUTH rule: do NOT put secrets in JSON body; secret must be URL query param.
  if (
    payload &&
    typeof payload === "object" &&
    ("secret" in payload || "WEBHOOK_SECRET" in payload || "webhook_secret" in payload)
  ) {
    res.status(400).json({
      ok: false,
      error: "secret_in_body_forbidden",
      detail: "Put secret in URL query string ?secret=..., not in JSON body.",
    });
    return;
  }

  const sourceIp = getSourceIp(req);
  const userAgent = (req.headers["user-agent"] || "").toString() || null;

  try {
    await pool.query(
      "insert into raw_events (path, source_ip, user_agent, payload) values ($1, $2, $3, $4)",
      [req.path, sourceIp, userAgent, payload]
    );
    res.json({ ok: true, parse_ok: payload?._parse_ok !== false });
  } catch (e) {
    console.error("DB insert failed:", e);
    res.status(500).json({
      ok: false,
      error: "db_insert_failed",
      detail: { message: e.message, code: e.code },
    });
  }
}

// TradingView endpoint (required by B1M_TRUTH)
app.post("/tv", handleWebhook);

// Optional generic endpoint
app.post("/webhook", handleWebhook);

// Export so you can SEE the rows landed
app.get("/export/raw_events", async (req, res) => {
  if (!requireSecret(req, res)) return;

  const limit = Math.min(parseInt(req.query.limit || "200", 10) || 200, 5000);

  try {
    const r = await pool.query(
      "select id, received_at, path, source_ip, user_agent, payload from raw_events order by received_at desc limit $1",
      [limit]
    );
    res.json({ ok: true, limit, row_count: r.rows.length, rows: r.rows });
  } catch (e) {
    res.status(500).json({
      ok: false,
      error: "export_failed",
      detail: { message: e.message, code: e.code },
    });
  }
});

ensureSchema()
  .then(() => {
    app.listen(PORT, "0.0.0.0", () => console.log(`listening on ${PORT}`));
  })
  .catch((e) => {
    console.error("Schema init failed:", e);
    process.exit(1);
  });