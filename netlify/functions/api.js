
// PishGuard API (Netlify Function, v2 runtime).
//   GET  /api/dashboard  -> summary + recent scans from the database
//   POST /api/scan       -> scan a URL, email address, email message or file hash
// Detection is rule-based (heuristics) plus VirusTotal. The server never visits
// a scanned URL; it only analyses the text and queries VirusTotal.
import * as database from "./lib/database.js";
import * as emailAnalyzer from "./lib/emailAnalyzer.js";
import * as heuristics from "./lib/heuristics.js";
import * as virustotal from "./lib/virustotal.js";
 
const MAX_BODY = 64 * 1024;
const MAX_VT_LINKS = 3;                      // VirusTotal lookups per pasted email
const RATE_LIMIT = parseInt(process.env.RATE_LIMIT_PER_MINUTE || "15", 10);
const CLIENT_ID_RE = /^[A-Za-z0-9-]{16,64}$/;
const hits = new Map();                      // per-instance sliding window
 
class ScanError extends Error {
  constructor(message, status = 400) { super(message); this.status = status; }
}
 
function rateLimited(ip) {
  const now = Date.now();
  const win = (hits.get(ip) || []).filter((t) => now - t < 60000);
  if (win.length >= RATE_LIMIT) { hits.set(ip, win); return true; }
  win.push(now);
  hits.set(ip, win);
  if (hits.size > 5000) for (const [k, v] of hits) if (!v.length) hits.delete(k);
  return false;
}
 
function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      "x-frame-options": "DENY",
      "referrer-policy": "no-referrer",
      ...extra,
    },
  });
}
 
const short = (v, limit = 500) => (v.length <= limit ? v : v.slice(0, limit - 1) + "…");
 
async function vtLookup(fn, ...args) {
  try { return [await fn(...args), null]; }
  catch (e) { if (e instanceof virustotal.VTError) return [null, e.message]; throw e; }
}
 
// ---- scanners -------------------------------------------------------------
async function scanUrl(value) {
  const h = heuristics.analyzeUrl(value);
  const [vt, notice] = await vtLookup(virustotal.checkUrl, h.normalized_url);
  const signals = [...h.signals];
  const vs = heuristics.vtSignal(vt);
  if (vs) signals.unshift(vs);
  return { input_type: "url", target: h.hostname, heuristic_score: h.score,
    risk_score: heuristics.combineScores(h.score, vt), vt, signals,
    notices: notice ? [notice] : [], links: [] };
}
 
async function scanEmailAddress(value) {
  const domain = value.split("@").pop().toLowerCase();
  const h = heuristics.analyzeUrl("https://" + domain);
  const [vt, notice] = await vtLookup(virustotal.checkDomain, domain);
  const notices = notice ? [notice] : [];
  if (vt === null && !notice) notices.push("VirusTotal has no record of this domain yet.");
  const signals = [...h.signals];
  const vs = heuristics.vtSignal(vt);
  if (vs) signals.unshift(vs);
  return { input_type: "email", target: value, heuristic_score: h.score,
    risk_score: heuristics.combineScores(h.score, vt), vt, signals, notices, links: [] };
}
 
async function scanHash(value) {
  let vt;
  try { vt = await virustotal.checkHash(value.toLowerCase()); }
  catch (e) {
    if (e instanceof virustotal.VTNotConfigured) throw new ScanError("File hash lookups need a VirusTotal API key. Add VT_API_KEY to your environment and try again.", 503);
    if (e instanceof virustotal.VTRateLimited) throw new ScanError(e.message, 429);
    if (e instanceof virustotal.VTError) throw new ScanError(e.message, 502);
    throw e;
  }
  if (vt === null) throw new ScanError("VirusTotal has no record of this file hash. PishGuard does not upload files.", 404);
  const kind = { 32: "MD5", 40: "SHA-1", 64: "SHA-256" }[value.length];
  return { input_type: "hash", target: value.toLowerCase(), heuristic_score: 0,
    risk_score: heuristics.combineScores(0, vt), vt,
    signals: [heuristics.vtSignal(vt), { id: "hash_type", severity: "info", triggered: false, weight: 0,
      title: "Hash type: " + kind, detail: "Looked up on VirusTotal by hash" }],
    notices: [], links: [] };
}
 
async function scanEmailMessage(text) {
  const parsed = emailAnalyzer.analyzeEmail(text);
  const notices = [];
  const entries = [];
  for (const link of parsed.links) {
    try { entries.push({ h: heuristics.analyzeUrl(link), vt: null }); }
    catch (e) { if (!(e instanceof heuristics.InvalidInput)) throw e; }
  }
  entries.sort((a, b) => b.h.score - a.h.score);
 
  let vtAvailable = true;
  for (const entry of entries.slice(0, MAX_VT_LINKS)) {
    if (!vtAvailable) break;
    const [vt, notice] = await vtLookup(virustotal.checkUrl, entry.h.normalized_url);
    if (notice) { notices.push(notice); vtAvailable = false; }
    entry.vt = vt;
  }
  if (entries.length > MAX_VT_LINKS && vtAvailable) {
    notices.push(`VirusTotal was checked for the ${MAX_VT_LINKS} riskiest links (free-tier friendly).`);
  }
 
  const rows = entries.map((e) => {
    const final = heuristics.combineScores(e.h.score, e.vt);
    return { url: short(e.h.normalized_url, 300), host: e.h.hostname, heuristic_score: e.h.score,
      risk_score: final, verdict: heuristics.verdictFor(final), vt: e.vt, _signals: e.h.signals };
  });
 
  const worst = rows.reduce((w, r) => (!w || r.risk_score > w.risk_score ? r : w), null);
  const headerScore = parsed.header_score;
  const heuristicScore = Math.min(100, headerScore + Math.max(0, ...rows.map((r) => r.heuristic_score)));
  const finalScore = Math.min(100, headerScore + (worst ? worst.risk_score : 0));
 
  let signals = [...parsed.signals];
  if (worst) {
    for (const s of worst._signals) if (s.triggered) signals.push({ ...s, title: "Link: " + s.title });
    const vs = heuristics.vtSignal(worst.vt);
    if (vs) signals.unshift({ ...vs, title: "Link: " + vs.title });
  }
  if (!signals.length) {
    signals.push({ id: "nothing", severity: "info", triggered: false, weight: 0,
      title: "Nothing to analyse", detail: "No sender headers or links were found in the pasted text" });
  } else if (!signals.some((s) => s.triggered)) {
    const good = signals.filter((s) => s.severity === "good").slice(0, 6);
    if (good.length) signals = good;
  }
 
  let bestVt = null;
  for (const r of rows) if (r.vt && (!bestVt || r.vt.malicious > bestVt.malicious)) bestVt = r.vt;
  for (const r of rows) delete r._signals;
 
  const sender = parsed.from || "unknown sender";
  const target = `From ${sender} · ${rows.length} link${rows.length === 1 ? "" : "s"} found`;
  return { input_type: "email", target, heuristic_score: heuristicScore, risk_score: finalScore,
    vt: bestVt, signals, notices, links: rows, stored_value: "Email: " + target };
}
 
// ---- routes ---------------------------------------------------------------
// Each browser sends its own random ID, so visitors only ever see their own history.
function clientIdOf(req) {
  const id = req.headers.get("x-client-id") || "";
  return CLIENT_ID_RE.test(id) ? id : "anonymous";
}
 
async function handleDashboard(clientId) {
  try {
    return json({ db_ok: true, summary: await database.getSummary(clientId), recent: await database.getRecent(10, clientId),
      storage: database.backendName() });
  } catch (e) {
    if (e instanceof database.DatabaseError) return json({ db_ok: false, summary: null, recent: [] });
    throw e;
  }
}
 
async function handleClear(ip, clientId) {
  if (rateLimited(ip)) return json({ error: "Too many requests. Please wait a minute." }, 429, { "retry-after": "60" });
  try {
    await database.clearHistory(clientId);
    return json({ ok: true });
  } catch (e) {
    if (e instanceof database.DatabaseError) return json({ error: "History could not be cleared (database unavailable)." }, 503);
    throw e;
  }
}
 
async function handleScan(req, ip, clientId) {
  if (rateLimited(ip)) return json({ error: "Too many scans. Please wait a minute and try again." }, 429, { "retry-after": "60" });
 
  const raw = await req.text();
  if (raw.length > MAX_BODY) return json({ error: "Input is too large." }, 413);
  let payload;
  try { payload = JSON.parse(raw); } catch { payload = null; }
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return json({ error: "Invalid request." }, 400);
 
  let result, value;
  try {
    value = heuristics.sanitizeInput(payload.input);
    let kind = heuristics.detectInputType(value);
    if (payload.mode === "email" && (kind === "url" || kind === "email_message")) kind = "email_message";
    if (kind === "hash") result = await scanHash(value);
    else if (kind === "email_address") result = await scanEmailAddress(value);
    else if (kind === "email_message") result = await scanEmailMessage(value);
    else result = await scanUrl(value);
  } catch (e) {
    if (e instanceof heuristics.InvalidInput) return json({ error: e.message }, 400);
    if (e instanceof ScanError) return json({ error: e.message }, e.status);
    console.error("Unexpected error while scanning:", e?.name);
    return json({ error: "Something went wrong while scanning. Please try again." }, 500);
  }
 
  const verdict = heuristics.verdictFor(result.risk_score);
  const storedValue = result.stored_value || short(value);
  delete result.stored_value;
 
  let saved = true;
  try {
    await database.saveScan(storedValue, result.input_type, verdict, result.risk_score,
      result.heuristic_score, result.vt, result.signals, clientId);
  } catch (e) {
    if (!(e instanceof database.DatabaseError)) throw e;
    saved = false;
  }
  return json({ ...result, verdict, input: short(value, 300), saved,
    db_notice: saved ? null : "History could not be saved (database unavailable)." });
}
 
export default async (req, context) => {
  const { pathname } = new URL(req.url);
  const ip = context?.ip || req.headers.get("x-nf-client-connection-ip") ||
    (req.headers.get("x-forwarded-for") || "").split(",")[0].trim() || "unknown";
  try {
    const clientId = clientIdOf(req);
    if (pathname === "/api/dashboard") return req.method === "GET" ? await handleDashboard(clientId) : json({ error: "Method not allowed." }, 405);
    if (pathname === "/api/scan") return req.method === "POST" ? await handleScan(req, ip, clientId) : json({ error: "Method not allowed." }, 405);
    if (pathname === "/api/clear") return req.method === "POST" ? await handleClear(ip, clientId) : json({ error: "Method not allowed." }, 405);
    return json({ error: "Not found." }, 404);
  } catch {
    return json({ error: "Internal server error." }, 500);
  }
};
 
export const config = { path: ["/api/dashboard", "/api/scan", "/api/clear"] };