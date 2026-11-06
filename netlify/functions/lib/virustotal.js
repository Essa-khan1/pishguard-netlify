// Minimal VirusTotal API v3 client. PishGuard never visits a scanned URL itself;
// it only sends the URL text (or domain / file hash) to VirusTotal.
// Free keys allow 4 requests/minute, so request counts are kept low and a 429
// response becomes a friendly message.
const BASE_URL = "https://www.virustotal.com/api/v3";
const GUI_URL = "https://www.virustotal.com/gui";

export class VTError extends Error {}
export class VTNotConfigured extends VTError {}
export class VTRateLimited extends VTError {}

export const isConfigured = () => !!(process.env.VT_API_KEY || "").trim();
export const urlId = (url) => Buffer.from(url, "utf8").toString("base64url"); // no padding

async function request(method, path, body) {
  const key = (process.env.VT_API_KEY || "").trim();
  if (!key) throw new VTNotConfigured("VirusTotal is not configured (set VT_API_KEY). Showing the heuristic result only.");
  let resp;
  try {
    resp = await fetch(BASE_URL + path, {
      method, body,
      headers: { "x-apikey": key, accept: "application/json" },
      signal: AbortSignal.timeout(7000),
    });
  } catch {
    throw new VTError("Could not reach VirusTotal. Showing the heuristic result only.");
  }
  if (resp.status === 429) throw new VTRateLimited("VirusTotal free-tier limit reached (4 requests per minute). Please wait about a minute and scan again.");
  if (resp.status === 401 || resp.status === 403) throw new VTError("VirusTotal rejected the API key. Please check VT_API_KEY.");
  if (resp.status >= 400 && resp.status !== 404) throw new VTError(`VirusTotal returned an error (${resp.status}). Please try again later.`);
  return resp;
}

function result(stats, status, link) {
  stats = stats || {};
  const n = (k) => parseInt(stats[k] || 0, 10) || 0;
  const malicious = n("malicious"), suspicious = n("suspicious"), harmless = n("harmless"), undetected = n("undetected");
  return { malicious, suspicious, harmless, undetected,
    total: malicious + suspicious + harmless + undetected, status, permalink: link };
}

async function attributes(resp) {
  try { return (await resp.json()).data.attributes; }
  catch { throw new VTError("VirusTotal returned an unexpected response."); }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export async function checkUrl(url) {
  const id = urlId(url);
  const link = `${GUI_URL}/url/${id}`;
  const resp = await request("GET", "/urls/" + id);
  if (resp.status === 404) return submitAndPoll(url, link);
  const stats = (await attributes(resp)).last_analysis_stats || {};
  if (Object.values(stats).reduce((a, v) => a + Number(v), 0) === 0) return submitAndPoll(url, link);
  return result(stats, "found", link);
}

async function submitAndPoll(url, link) {
  const resp = await request("POST", "/urls", new URLSearchParams({ url }));
  let analysisId;
  try { analysisId = (await resp.json()).data.id; }
  catch { throw new VTError("VirusTotal returned an unexpected response."); }

  // Netlify functions time out after ~10 s on the free plan, so polling is short.
  const interval = parseFloat(process.env.VT_POLL_INTERVAL || "2") * 1000;
  const maxPolls = parseInt(process.env.VT_MAX_POLLS || "2", 10);
  for (let i = 0; i < maxPolls; i++) {
    await sleep(interval);
    let poll;
    try { poll = await request("GET", "/analyses/" + analysisId); }
    catch (e) { if (e instanceof VTRateLimited) break; throw e; }
    const attrs = await attributes(poll);
    if (attrs.status === "completed") return result(attrs.stats, "submitted", link);
  }
  return result({}, "pending", link);
}

async function lookup(path, guiPath) {
  const resp = await request("GET", path);
  if (resp.status === 404) return null;
  const stats = (await attributes(resp)).last_analysis_stats || {};
  return result(stats, "found", `${GUI_URL}/${guiPath}`);
}

export const checkDomain = (domain) => lookup("/domains/" + encodeURIComponent(domain), "domain/" + encodeURIComponent(domain));
export const checkHash = (hash) => lookup("/files/" + encodeURIComponent(hash), "file/" + encodeURIComponent(hash));
