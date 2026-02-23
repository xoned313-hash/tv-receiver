import pg from "pg";

const { Pool } = pg;

const DATABASE_URL = (process.env.DATABASE_URL || "").trim();
if (!DATABASE_URL) {
  console.error("FATAL: DATABASE_URL is not set");
  process.exit(1);
}

function pgSslConfig() {
  const ca = process.env.DATABASE_CA_CERT || process.env.CA_CERT || "";
  if (ca.trim().length > 0) {
    return {
      rejectUnauthorized: true,
      ca: ca.replace(/\\n/g, "\n"),
    };
  }
  if (process.env.PGSSL_INSECURE === "1") {
    return { rejectUnauthorized: false };
  }
  // Default: keep encrypted connections working even if CA is not provided.
  return { rejectUnauthorized: false };
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: pgSslConfig(),
  max: 5,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 10_000,
});

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function ensureMaterializerSchema() {
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
  // We use dedup as the primary key if it exists; your payload already includes "dedup"
  // like: BAR|BINANCE:BTCUSDT.P|15|1771794900000
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

async function materializeBatch(batchSize = 200) {
  const client = await pool.connect();
  let fetched = 0;
  let inserted = 0;

  try {
    await client.query("begin");

    const st = await client.query(
      "select last_raw_event_id from materializer_state where id=1 for update"
    );
    const lastId = BigInt(st.rows[0].last_raw_event_id || 0);

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

        const dedup = String(rec.dedup || rec.uid || `${row.id}:${i}`);

        const q = await client.query(
          `
          insert into bars (
            dedup, raw_event_id, received_at,
            symbol, tf_sec, tf,
            t_open_ms, t_close_ms,
            open, high, low, close, volume,
            spot_close, oi_close, funding_rate,
            premium_pct, premium_idx,
            basis, basis_pct,
            long_accounts, short_accounts,
            liq_buy, liq_sell,
            payload
          ) values (
            $1, $2, $3,
            $4, $5, $6,
            $7, $8,
            $9, $10, $11, $12, $13,
            $14, $15, $16,
            $17, $18,
            $19, $20,
            $21, $22,
            $23, $24,
            $25
          )
          on conflict (dedup) do nothing
          `,
          [
            dedup,
            row.id,
            row.received_at,

            rec.symbol ?? null,
            rec.tf_sec ?? null,
            rec.tf ?? null,

            rec.t_open_ms ?? null,
            rec.t_close_ms ?? null,

            rec.open ?? null,
            rec.high ?? null,
            rec.low ?? null,
            rec.close ?? null,
            rec.volume ?? null,

            rec.spot_close ?? null,
            rec.oi_close ?? null,
            rec.funding_rate ?? null,

            rec.premium_pct ?? null,
            rec.premium_idx ?? null,

            rec.basis ?? null,
            rec.basis_pct ?? null,

            rec.long_accounts ?? null,
            rec.short_accounts ?? null,

            rec.liq_buy ?? null,
            rec.liq_sell ?? null,

            rec, // store the full record JSON
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
    } catch {}
    return { ok: false, error: `${e?.code || ""} ${e?.message || e}`.trim(), fetched, inserted };
  } finally {
    client.release();
  }
}

async function main() {
  await ensureMaterializerSchema();

  while (true) {
    const r = await materializeBatch(300);

    if (!r.ok) {
      console.error("materializer error:", r.error);
      await sleep(5000);
      continue;
    }

    if (r.fetched === 0) {
      // Nothing new — sleep briefly
      await sleep(5000);
      continue;
    }

    console.log(`materialized: fetched_raw=${r.fetched} inserted_bars=${r.inserted}`);
  }
}

main().catch((e) => {
  console.error("FATAL:", e);
  process.exit(1);
});
