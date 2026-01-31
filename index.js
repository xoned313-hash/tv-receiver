import express from "express";
import pkg from "pg";

const { Pool } = pkg;

const app = express();

// Accept *any* TradingView body (often arrives as text/plain).
// We'll parse JSON manually when possible.
app.use(express.text({ type: "*/*", limit: "1mb" }));

const DATABASE_URL = process.env.DATABASE_URL;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;

if (!DATABASE_URL) {
  console.warn("WARNING: DATABASE_URL is not set");
}
if (!WEBHOOK_SECRET) {
  console.warn("WARNING: WEBHOOK_SECRET is not set");
}

// Postgres connection.
// For managed Postgres, SSL is commonly required.
// If you ever run locally against a non-SSL DB, set PGSSLMODE=disable.
const ssl =
  process.env.PGSSLMODE === "disable" ? false : { rejectUnauthorized: false };

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl,
});

function authOk(req) {
  const secret = req.query.secret;
  return Boolean(secret && WEBHOOK_SECRET && secret === WEBHOOK_SECRET);
}

function parsePayload(req) {
  // req.body is always a string because we used express.text()
  const raw = (req.body ?? "").trim();

  if (!raw) {
    return { _parse_ok: false, _error: "empty_body" };
  }

  try {
    return JSON.parse(raw);
  } catch (e) {
    // Store something valid in jsonb even if parsing fails
    return {
      _parse_ok: false,
      _error: "json_parse_failed",
      _raw: raw.slice(0, 5000), // safety cap
    };
  }
}

/**
 * HEALTH CHECK
 */
app.get("/healthz", async (req, res) => {
  try {
    const r = await pool.query("select now()");
    res.json({
      ok: true,
      db_ok: true,
      now: r.rows[0].now,
      webhook_secret_configured: Boolean(WEBHOOK_SECRET),
    });
  } catch (err) {
    res.status(500).json({ ok: false, error: String(err.message || err) });
  }
});

/**
 * WEBHOOK RECEIVER (RAW)
 * Supports both /webhook and /tv to avoid "wrong path" mistakes.
 */
async function handleWebhook(req, res) {
  if (!authOk(req)) {
    return res.status(401).json({ ok: false, error: "unauthorized" });
  }

  const payload = parsePayload(req);

  try {
    await pool.query(
      `
      insert into raw_events (received_at, payload)
      values (now(), $1::jsonb)
      `,
      [JSON.stringify(payload)]
    );

    res.json({ ok: true, parse_ok: payload?._parse_ok !== false });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: "db_insert_failed" });
  }
}

app.post("/webhook", handleWebhook);
app.post("/tv", handleWebhook);

/**
 * QUICK ROW COUNT (for debugging)
 */
app.get("/count", async (req, res) => {
  if (!authOk(req)) {
    return res.status(401).json({ ok: false, error: "unauthorized" });
  }

  try {
    const r = await pool.query("select count(*)::bigint as n from raw_events");
    res.json({ ok: true, count: Number(r.rows[0].n) });
  } catch (err) {
    res.status(500).json({ ok: false, error: String(err.message || err) });
  }
});

/**
 * EXPORT (so you can upload data to ChatGPT like you used to with Sheets)
 * Example:
 *  /export?secret=...&minutes=60&limit=5000
 */
app.get("/export", async (req, res) => {
  if (!authOk(req)) {
    return res.status(401).json({ ok: false, error: "unauthorized" });
  }

  const minutes = Math.max(1, Math.min(1440, Number(req.query.minutes || 60)));
  const limit = Math.max(1, Math.min(20000, Number(req.query.limit || 5000)));

  try {
    const r = await pool.query(
      `
      select received_at, payload
      from raw_events
      where received_at >= now() - ($1::int * interval '1 minute')
      order by received_at asc
      limit $2
      `,
      [minutes, limit]
    );

    res.json({
      ok: true,
      minutes,
      limit,
      rows: r.rows,
    });
  } catch (err) {
    res.status(500).json({ ok: false, error: String(err.message || err) });
  }
});

const port = process.env.PORT || 8080;
app.listen(port, "0.0.0.0", () => {
  console.log("listening on", port);
});