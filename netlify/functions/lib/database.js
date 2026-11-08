// Database access for PishGuard (Netlify edition).
// Uses Neon Postgres over HTTPS when DATABASE_URL is set; otherwise falls back to
// an in-memory list so the app still runs without any setup (history is then
// temporary and is lost when the function instance restarts).
// Serverless-friendly: no persistent connection, every query is a single HTTPS
// request, and every query is parameterized.
const SCHEMA = `CREATE TABLE IF NOT EXISTS scans (
  id SERIAL PRIMARY KEY,
  input_value TEXT NOT NULL,
  input_type TEXT NOT NULL,
  verdict TEXT NOT NULL,
  risk_score INTEGER NOT NULL,
  heuristic_score INTEGER NOT NULL DEFAULT 0,
  vt_malicious INTEGER,
  vt_suspicious INTEGER,
  vt_harmless INTEGER,
  signals TEXT,
  client_id TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`;
 
export class DatabaseError extends Error {}
 
const databaseUrl = () => (process.env.DATABASE_URL || "").trim();
export const backendName = () => (databaseUrl() ? "postgres" : "memory");
 
let memory = [];
let nextId = 1;
export function _resetMemory() { memory = []; nextId = 1; }
 
const ready = new Set();
const sqlCache = new Map();
 
function withTimeout(promise, ms = 8000) {
  let timer;
  const timeout = new Promise((_, rej) => { timer = setTimeout(() => rej(new Error("timeout")), ms); });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}
 
async function pgQuery(text, params = []) {
  const url = databaseUrl();
  if (!/^postgres(ql)?:\/\//i.test(url)) throw new Error("bad DATABASE_URL");
  let sql = sqlCache.get(url);
  if (!sql) {
    const { neon } = await import("@neondatabase/serverless");
    sql = neon(url);
    sqlCache.set(url, sql);
  }
  if (!ready.has(url)) {
    await sql.query(SCHEMA);
    await sql.query("ALTER TABLE scans ADD COLUMN IF NOT EXISTS client_id TEXT");   // upgrade older tables
    await sql.query("CREATE INDEX IF NOT EXISTS scans_client_idx ON scans (client_id, id DESC)");
    ready.add(url);
  }
  return sql.query(text, params);
}
 
async function run(text, params, memoryFn) {
  try {
    if (backendName() === "memory") return memoryFn();
    return await withTimeout(pgQuery(text, params));
  } catch (err) {
    // Log only the error type so credentials never reach the logs.
    console.warn(`Database error (${backendName()}): ${err?.name || "Error"}`);
    throw new DatabaseError("The database is unavailable.");
  }
}
 
export async function initDb() {
  await run("SELECT 1 FROM scans WHERE 1 = 0", [], () => []);
}
 
export async function saveScan(inputValue, inputType, verdict, riskScore, heuristicScore = 0, vt = null, signals = null, clientId = "anonymous") {
  vt = vt || {};
  const params = [
    String(inputValue).slice(0, 500), String(inputType), String(verdict),
    Math.trunc(riskScore), Math.trunc(heuristicScore),
    vt.malicious ?? null, vt.suspicious ?? null, vt.harmless ?? null,
    JSON.stringify(signals || []),
    String(clientId),
  ];
  await run(
    "INSERT INTO scans (input_value, input_type, verdict, risk_score, heuristic_score, " +
    "vt_malicious, vt_suspicious, vt_harmless, signals, client_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
    params,
    () => {
      memory.push({ id: nextId++, input_value: params[0], input_type: params[1], verdict: params[2],
        risk_score: params[3], client_id: params[9], created_at: new Date().toISOString() });
      if (memory.length > 500) memory.shift();
      return [];
    });
}
 
export async function getSummary(clientId = "anonymous") {
  const rows = await run("SELECT verdict, COUNT(*) AS n FROM scans WHERE client_id = $1 GROUP BY verdict", [clientId], () => {
    const counts = {};
    for (const r of memory) if (r.client_id === clientId) counts[r.verdict] = (counts[r.verdict] || 0) + 1;
    return Object.entries(counts).map(([verdict, n]) => ({ verdict, n }));
  });
  const counts = { Phishing: 0, Suspicious: 0, Safe: 0 };
  let total = 0;
  for (const r of rows) {
    const n = Number(r.n);
    total += n;
    if (r.verdict in counts) counts[r.verdict] = n;
  }
  return { phishing: counts.Phishing, suspicious: counts.Suspicious, safe: counts.Safe, total };
}
 
export async function getRecent(limit = 10, clientId = "anonymous") {
  limit = Math.max(1, Math.min(parseInt(limit, 10) || 10, 100));
  const rows = await run(
    "SELECT id, input_value, input_type, verdict, risk_score, created_at FROM scans " +
    "WHERE client_id = $1 ORDER BY id DESC LIMIT $2",
    [clientId, limit],
    () => memory.filter((r) => r.client_id === clientId).reverse().slice(0, limit));
  return rows.map((r) => ({
    id: r.id, input_value: r.input_value, input_type: r.input_type,
    verdict: r.verdict, risk_score: r.risk_score, created_at: String(r.created_at),
  }));
}
 
/** Delete one visitor's history (never anyone else's). */
export async function clearHistory(clientId = "anonymous") {
  await run("DELETE FROM scans WHERE client_id = $1", [clientId], () => {
    memory = memory.filter((r) => r.client_id !== clientId);
    return [];
  });
}
