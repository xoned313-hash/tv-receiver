import pg from "pg";

const { Pool } = pg;

/**
 * materializer.js
 *
 * Reads raw_events and writes typed BAR rows into a query-friendly `bars` table.
 *
 * Compatibility stance:
 * - legacy receiver rows that stored bundle payloads in `payload`
 * - newer receiver rows that store one logical record per raw_events row in `payload_raw_redacted`
 *
 * Run command:
 *   npm run materializer
 */

const DATABASE_URL_RAW = (process.env.DATABASE_URL || "").trim();
if (!DATABASE_URL_RAW) {
  console.error("FATAL: DATABASE_URL is not set");
  process.exit(1);
}

const CA_CERT = (process.env.CA_CERT || process.env.DATABASE_CA_CERT || "").trim();
const PGSSL_INSECURE = (process.env.PGSSL_INSECURE || "").trim() === "1";

function scrubDbUrl(url) {
  if (!url) return "";
  try {
    const u = new URL(url);
    u.searchParams.delete("sslmode");
    return u.toString();
  } catch {
    return url.replace(/[?&]sslmode=[^&]+/i, "");
  }
}

function pgSslConfig() {
  const pgsslmode = (process.env.PGSSLMODE || "").toLowerCase();
  if (pgsslmode === "disable") return false;

  if (CA_CERT) {
    return {
      rejectUnauthorized: true,
      ca: CA_CERT.replace(/\\n/g, "\n")
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
  connectionTimeoutMillis: 10_000
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

async function ensureMaterializerSchema() {
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

  await pool.query(`
    create table if not exists bars (
      dedup text primary key,
      uid text,
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
    create unique index if not exists bars_uid_uq
    on bars (uid)
    where uid is not null;
  `);

  await pool.query(`
    create index if not exists bars_symbol_tf_close_idx
    on bars (symbol, tf_sec, t_close_ms desc);
  `);

  await pool.query(`
    create index if not exists bars_received_at_idx
    on bars (received_at desc);
  `);
}

function extractBarRecords(row) {
  const out = [];

  const directPayload = asObject(row.payload_raw_redacted) || asObject(row.payload);
  if (row.row_type === "BAR" && directPayload) {
    out.push(directPayload);
    return out;
  }

  if (directPayload && Array.isArray(directPayload.records)) {
    for (const rec of directPayload.records) {
      const obj = asObject(rec);
      if (obj && obj.row_type === "BAR") out.push(obj);
    }
    return out;
  }

  if (directPayload && directPayload.row_type === "BAR") {
    out.push(directPayload);
  }

  return out;
}

async function materializeBatch(batchSize = 300) {
  const client = await pool.connect();
  let fetched = 0;
  let inserted = 0;

  try {
    await client.query("begin");

    const st = await client.query(
      "select last_raw_event_id from materializer_state where id = 1 for update"
    );
    const lastId = BigInt(st.rows[0].last_raw_event_id || 0);

    const rs = await client.query(
      `
        select
          id,
          received_at,
          row_type,
          payload_raw_redacted,
          payload
        from raw_events
        where id > $1
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

      const records = extractBarRecords(row);

      for (let i = 0; i < records.length; i++) {
        const rec = asObject(records[i]) || {};
        const symbol = (rec.symbol || "").toString();
        const tfSec = toInt(rec.tf_sec);

        if (!symbol || tfSec === null) continue;

        const dedup = String(rec.dedup || rec.uid || `${row.id}:${i}`);
        const uid = rec.uid ? String(rec.uid) : null;

        const q = await client.query(
          `
            insert into bars (
              dedup,
              uid,
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
              $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26
            )
            on conflict (dedup) do nothing
          `,
          [
            dedup,
            uid,
            row.id,
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
            rec
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
      // ignore
    }
    return {
      ok: false,
      error: `${e?.code || ""} ${e?.message || e}`.trim(),
      fetched,
      inserted
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

    console.log(`materialized: fetched_raw=${r.fetched} inserted_bars=${r.inserted}`);
  }
}

main().catch((e) => {
  console.error("FATAL:", e);
  process.exit(1);
});
