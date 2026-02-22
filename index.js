import express fr:contentReference[oaicite:9]{index=9}kg from "pg";

const { Pool } = pkg;
const app = express();

// TradingView often sends text/plain, so accept everything as text and parse ourselves.
app.use(express.text({ type: "*/*", limit: "1mb" }));

const PORT = parseInt(process.env.PORT || "8080", 10);
const DATABASE_URL = (process.env.DATABASE_URL || "").trim();
const WEBHOOK_SECRET = (process.env.WEBHOOK_SECRET || "").trim();

// DigitalOcean naming varies depending on how you wired env vars.
// We'll accept either CA_CERT or DATABASE_CA_CERT.
function normalizeCert(s) {
  if (!s) return "";
  // If the cert is stored with literal "\n", convert it back into real newlines.
  return s.includes("\\n") ? s.replace(/\\n/g, "\n") : s;
}
const CA_CERT = normalizeCert(process.env.CA_CERT || process.env.DATABASE_CA_CERT || "");

// SECURITY: In production you want verify ON (rejectUnauthorized: true) AND you must provide the CA cert.
const sslConfig = CA_CERT
  ? { rejectUnauthorized: true, ca: CA_CERT }
  : null;

// Build pool config WITHOUT passing the full connectionString directly,
// because `?sslmode=require` can override SSL options in node-postgres.
function poolConfigFromDatabaseUrl(dbUrl) {
  const u = new URL(dbUrl);

  return {
    host: u.hostname,
    port: u.port ? parseInt(u.port, 10) : 5432,
    database: (u.pathname || "").replace(/^\//, ""),
    user: decodeURIComponent(u.username || ""),
    password: decodeURIComponent(u.password || ""),
    ssl: sslConfig || { rejectUnauthorized: false }, // dev-only fallback if CA_CERT missing
    max: 5,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 10_000,
  };
}

const pool = DATABASE_URL
  ? new Pool(poolConfigFromDatabaseUrl(DATABASE_URL))
  : new Pool({
      host: process.env.DB_HOST,
      port: parseInt(process.env.DB_PORT || "5432", 10),
      database: process.env.DB_NAME,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      ssl: sslConfig || { rejectUnauthorized: false }, // dev-only fallback
      max: 5,
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 10_000,
    });

function authOk(req) {
  const secret = String(req.query.secret || "");
  return Boolean(secret && WEBHOOK_SECRET && secret === WEBHOOK_SECRET);
}

function parsePayload(req) {
  const raw = String(req.body || "").trim();
  if (!raw) return { _parse_ok: false, _error: "empty_body" };

  try {
    return JSON.parse(raw);
  } catch {
    // Store something valid in jsonb even if parsing fails
    return { _parse_ok: false, _error: "json_parse_failed", _raw: raw.slice(0, 5000) };
  }
}

async function ensureSchema() {
  // Auto-create the table so you don't have to do manual DB steps.
  await pool.query(`
    create table if not exists raw_events (
      id bigserial primary key,
      received_at timestamptz not null default now(),
      path text,
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

/**
 * HEALTH CHECK
 * Visit: https://YOURAPP.ondigitalocean.app/healthz
 */
app.get("/healthz", async (req, res) => {
  const now = new Date().toISOString();
  try {
    await pool.query("select 1 as ok");
    const c = await pool.query("select count(*)::bigint as n from raw_events");
    res.json({
      ok: true,
      now,
      db_ok: true,
      raw_events_count: c.rows?.[0]?.n ?? null,
      webhook_secret_configured: Boolean(WEBHOOK_SECRET),
      ca_cert_configured: Boolean(CA_CERT),
    });
  } catch (err) {
    res.status(500).json({
      ok: false,
      now,
      error: String(err?.message || err),
      ca_cert_configured: Boolean(CA_CERT),
    });
  }
});

/**
 * WEBHOOK RECEIVER
 * POST /tv?secret=...
 * POST /webhook?secret=...
 */
async function handleWebhook(req, res) {
  if (!authOk(req)) return res.status(401).json({ ok: false, error: "unauthorized" });

  const payload = parsePayload(req);

  const sourceIp =
    String(req.headers["x-forwarded-for"] || "").split(",")[0].trim() ||
    req.socket?.remoteAddress ||
    null;

  const userAgent = String(req.headers["user-agent"] || "") || null;

  try {
    await pool.query(
      `insert into raw_events (path, source_ip, user_agent, payload)
       values ($1, $2, $3, $4::jsonb)`,
      [req.path, sourceIp, userAgent, JSON.stringify(payload)]
    );
    res.json({ ok: true, parse_ok: payload?._parse_ok !== false });
  } catch (err) {
    console.error("DB insert failed:", err);
    res.status(500).json({ ok: false, error: "db_insert_failed", detail: String(err?.message || err) });
  }
}

app.post("/tv", handleWebhook);
app.post("/webhook", handleWebhook);

/**
 * QUICK ROW COUNT (debug)
 * Visit: /count?secret=...
 */
app.get("/count", async (req, res) => {
  if (!authOk(req)) return res.status(401).json({ ok: false, error: "unauthorized" });
  try {
    const r = await pool.query("select count(*)::bigint as n from raw_events");
    res.json({ ok: true, count: Number(r.rows[0].n) });
  } catch (err) {
    res.status(500).json({ ok: false, error: String(err?.message || err) });
  }
});

/**
 * EXPORT (debug)
 * Visit: /export?secret=...&minutes=60&limit=5000
 */
app.get("/export", async (req, res) => {
  if (!authOk(req)) return res.status(401).json({ ok: false, error: "unauthorized" });

  const minutes = Math.max(1, Math.min(1440, Number(req.query.minutes || 60)));
  const limit = Math.max(1, Math.min(20000, Number(req.query.limit || 5000)));

  try {
    const r = await pool.query(
      `select id, received_at, path, payload
       from raw_events
       where received_at >= now() - ($1::int * interval '1 minute')
       order by received_at asc
       limit $2`,
      [minutes, limit]
    );
    res.json({ ok: true, minutes, limit, rows: r.rows });
  } catch (err) {
    res.status(500).json({ ok: false, error: String(err?.message || err) });
  }
});

ensureSchema()
  .then(() => {
    app.listen(PORT, "0.0.0.0", () => console.log("listening on", PORT));
  })
  .catch((e) => {
    console.error("Schema init failed:", e);
    process.exit(1);
  });
