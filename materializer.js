import pg from "pg";

const { Pool } = pg;

/**
 * materializer.js
 *
 * Reads raw_events (inserted by the receiver /tv endpoint)
 * and writes typed BAR rows into a "bars" table (dedup primary key).
 *
 * Run command (per package.json): npm run materializer
 */

const DATABASE_URL_RAW = (process.env.DATABASE_URL || "").trim();
if (!DATABASE_URL_RAW) {
  console.error("FATAL: DATABASE_URL is not set");
  process.exit(1);
}

// DigitalOcean DB component commonly provides CA cert via ${.CA_CERT}.
// Support both names (and keep compatibility with prior setup).
const CA_CERT = (process.env.CA_CERT || process.env.DATABASE_CA_CERT || "").trim();

// Set PGSSL_INSECURE=1 ONLY for a temporary debug bypass.
const PGSSL_INSECURE = (process.env.PGSSL_INSECURE || "").trim() === "1";

/**
 * Scrub sslmode from DATABASE_URL so our explicit `ssl:` config is the single source of truth.
 * This avoids "sslmode" parsing quirks / overrides in some Node pg flows.
 */
function scrubDbUrl(url) {
  if (!url) return "";
  try {
    const u = new URL(url);
    u.searchParams.delete("sslmode");
    return u.toString();
  } catch {
    // Fallback if URL() can't parse (older/odd formats)
    return url.replace(/[?&]sslmode=[^&]+/i, "");
  }
}

/**
 * TLS strategy (same approach as receiver):
 * - If PGSSLMODE=disable => no SSL (not recommended for managed DBs).
 * - If CA_CERT present => verify TLS (recommended).
 * - Else if PGSSL_INSECURE=1 => encrypt but do not verify (debug only).
 * - Else => fail closed (forces correct CA config).
 */
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

  // Fail closed by default (forces proper CA configuration).
  return { rejectUnauthorized: true };
}

const pool = new Pool({
  connectionString: scrubDbUrl(DATABASE_URL_RAW),
  ssl: pgSslConfig(),
  max: 5,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 10_000,
});

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
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

function toInt(x) {
  if (x === null || x === undefined || x === "") return null;
  const n = Number(x);
  return Number.isFinite(n) ? Math.trunc(n) : null;
}

function toFloat(x) {
  if (x === null || x === undefined || x === "") return null;
  const n = Number(x);
  return Number.isFinite(n) ? n : null;
}

/**
 * Make the worker resilient if it starts before the receiver has created / migrated raw_events.
 * This mirrors the receiver’s forward-migration behavior.
 */
async function ensureRawEventsSchema() {
  await pool.query(`
    create table if not exists raw_events (
      id bigserial primary key,
      received_at timestamptz not null default now(),
      payload jsonb not null
    );
  `);

  await pool.query(`alter table raw_events add column if not exists path text;`);
  await pool.query(`alter table raw_events add column if not exists source_ip text;`);
  await pool.query(`alter table raw_events add column if not exists user_agent text;`);

  await pool.query(`
    create index if not exists raw_events_received_at_idx
    on raw_events (received_at desc);
  `);
}

async function ensureMaterializerSchema() {
  await ensureRawEventsSchema();

  // 1) State table: remembers how far we got in raw_events
  await pool.query(`
    create table if not exists materializer_state (
      id int primary key,
      last_raw_event_id bigint not null default 0,
      updated_at timestamptz not null default now()
    );
  `);

  await pool.query(`
    insert into materializer_state (id, last_raw_event_id)
    values (1, 0)
    on conflict (id) do nothing;
  `);

  // 2) Typed table: bars
  // We use dedup as the primary key if it exists; payload includes "dedup" like:
  // BAR|BINANCE:BTCUSDT.P|15|1771794900000
  await pool.query(`
    create table if not exists bars (
      dedup text primary key,

      raw_event_id bigint not null,
      received_at timestamptz not null,

      symbol text not null,
      tf_sec int not null,
      tf text,

      t_open_ms bigint,
      t_close_ms bigint,

      open double precision,
      high double precision,
      low double precision,
      close double precision,
      volume double precision,

      spot_close double precision,
      oi_close double precision,
      funding_rate double precision,
      premium_pct double precision,
      premium_idx double precision,
      basis double precision,
      basis_pct double precision,

      long_accounts double precision,
      short_accounts double precision,

      liq_buy double precision,
      liq_sell double precision,

      payload jsonb not null
    );
  `);

  await pool.query(`
    create index if not exists bars_symbol_tf_close_idx
    on bars (symbol, tf_sec, t_close_ms desc);
  `);

  await pool.query(`
    create index if not exists bars_received_at_idx
    on bars (received_at desc);
  `);

  console.log("materializer schema OK");
}

async function materializeBatch(batchSize = 300) {
  const client = await pool.connect();
  let fetched = 0;
  let inserted = 0;

  try {
    await client.query("begin");

    const st = await client.query(
      "select last_raw_event_id from materializer_state where id=1 for update"
    );
    const lastId = BigInt(st.rows[0].last_raw_event_id || 0);

    // Only materialize TradingView webhook rows
    const rs = await client.query(
      `
        select id, received_at, path, payload
        from raw_events
        where id > $1
          and path = '/tv'
        order by id asc
        limit $2
      `,
      [lastId.toString(), batchSize]
    );

    fetched = rs.rows.length;

    let newLast = lastId;

    for (const row of rs.rows) {
      const rawEventId = BigInt(row.id);
      if (rawEventId > newLast) newLast = rawEventId;

      const payload = asObject(row.payload);
      const records = Array.isArray(payload?.records) ? payload.records : [];

      for (let i = 0; i < records.length; i++) {
        const rec = asObject(records[i]) || {};

        if ((rec.row_type || "") !== "BAR") continue;

        const symbol = (rec.symbol || "").toString();
        const tfSec = toInt(rec.tf_sec);

        // Skip malformed BAR records (avoids NOT NULL violations)
        if (!symbol || tfSec === null) continue;

        const dedup = String(rec.dedup || rec.uid || `${row.id}:${i}`);

        const q = await client.query(
          `
            insert into bars (
              dedup,
              raw_event_id,
              received_at,
              symbol,
              tf_sec,
              tf,
              t_open_ms,
              t_close_ms,
              open,
              high,
              low,
              close,
              volume,
              spot_close,
              oi_close,
              funding_rate,
              premium_pct,
              premium_idx,
              basis,
              basis_pct,
              long_accounts,
              short_accounts,
              liq_buy,
              liq_sell,
              payload
            ) values (
              $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25
            )
            on conflict (dedup) do nothing
          `,
          [
            dedup,
            row.id, // bigint in DB; pg may return string; DB will cast
            row.received_at,

            symbol,
            tfSec,
            rec.tf ?? null,

            toInt(rec.t_open_ms),
            toInt(rec.t_close_ms),

            toFloat(rec.open),
            toFloat(rec.high),
            toFloat(rec.low),
            toFloat(rec.close),
            toFloat(rec.volume),

            toFloat(rec.spot_close),
            toFloat(rec.oi_close),
            toFloat(rec.funding_rate),
            toFloat(rec.premium_pct),
            toFloat(rec.premium_idx),
            toFloat(rec.basis),
            toFloat(rec.basis_pct),

            toFloat(rec.long_accounts),
            toFloat(rec.short_accounts),

            toFloat(rec.liq_buy),
            toFloat(rec.liq_sell),

            rec, // full record JSON
          ]
        );

        inserted += q.rowCount || 0;
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
    return { ok: true, fetched, inserted };
  } catch (e) {
    try {
      await client.query("rollback");
    } catch {
      // ignore rollback errors
    }
    return {
      ok: false,
      error: `${e?.code || ""} ${e?.message || e}`.trim(),
      fetched,
      inserted,
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
      // Nothing new
      await sleep(idleSleepMs);
      continue;
    }

    console.log(`materialized: fetched_raw=${r.fetched} inserted_bars=${r.inserted}`);
  }
}

main().catch((e) => {
  console.error("FATAL:", e);
  process.exit(1);
});