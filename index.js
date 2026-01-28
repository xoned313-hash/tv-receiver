import express from "express";
import pkg from "pg";

const { Pool } = pkg;

const app = express();
app.use(express.json({ limit: "1mb" }));

// Postgres connection
// NOTE: The ssl: { rejectUnauthorized: false } setting fixes the
// "self-signed certificate in certificate chain" error commonly seen
// with managed Postgres providers.
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

/**
 * HEALTH CHECK
 * Confirms the server is up and can reach Postgres.
 */
app.get("/healthz", async (req, res) => {
  try {
    const r = await pool.query("select now()");
    res.json({ ok: true, db_ok: true, now: r.rows[0].now });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

/**
 * WEBHOOK RECEIVER (RAW)
 * Stores every incoming request body into raw_events.payload.
 */
app.post("/webhook", async (req, res) => {
  const secret = req.query.secret;
  if (!secret || secret !== process.env.WEBHOOK_SECRET) {
    return res.status(401).json({ ok: false, error: "unauthorized" });
  }

  try {
    await pool.query(
      `
      insert into raw_events (received_at, payload)
      values (now(), $1)
      `,
      [req.body]
    );

    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: "db_insert_failed" });
  }
});

const port = process.env.PORT || 8080;
app.listen(port, "0.0.0.0", () => {
  console.log("listening on", port);
});
