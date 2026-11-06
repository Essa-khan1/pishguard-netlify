// Rule-based (heuristic) phishing analysis for PishGuard.
// Works on the TEXT of the input only. Nothing is ever fetched or visited.
// Each check is a signal with a weight; triggered weights add up (capped at 100).
import { isIP } from "node:net";

export const MAX_URL_LENGTH = 2048;
export const MAX_TEXT_LENGTH = 20000;
export const SAFE_MAX = 29;        // 0-29 Safe, 30-59 Suspicious, 60+ Phishing
export const SUSPICIOUS_MAX = 59;

export class InvalidInput extends Error {}

export const SUSPICIOUS_KEYWORDS = [
  "login", "signin", "sign-in", "verify", "verification", "secure", "security",
  "update", "account", "password", "confirm", "banking", "wallet", "suspend",
  "unlock", "billing", "invoice", "recover", "reset", "alert", "webscr", "authenticate",
];

export const SUSPICIOUS_TLDS = new Set([
  "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "work", "zip", "mov",
  "loan", "country", "kim", "men", "party", "review", "science", "support",
  "icu", "cyou", "buzz", "monster", "rest", "cam", "quest", "fit",
]);

const URL_SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
  "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "t.ly",
]);

// brand -> extra official registered domains
const BRANDS = {
  paypal: [], google: ["googleapis.com", "googleusercontent.com", "gstatic.com", "goo.gl"],
  microsoft: ["live.com", "office.com", "microsoftonline.com", "windows.net", "azure.com"],
  apple: ["icloud.com"], amazon: ["amazonaws.com", "amzn.to"], facebook: ["fb.com"],
  instagram: [], netflix: [], whatsapp: [], linkedin: [], dropbox: ["dropboxusercontent.com"],
  github: ["githubusercontent.com", "github.io"], binance: [], coinbase: [], metamask: [],
  ebay: [], outlook: [], office365: [], fedex: [], jazzcash: [], easypaisa: [],
  wellsfargo: [], bankofamerica: [],
};

const SECOND_LEVEL = new Set(["co", "com", "org", "net", "gov", "edu", "ac", "or", "ne", "go", "gob"]);

export const HASH_RE = /^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$/;
export const EMAIL_ADDR_RE = /^[A-Za-z0-9._%+\-']+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$/;
const HEADER_NAMES = "(?:from|to|subject|received|return-path|reply-to|message-id|date|mime-version|x-[\\w-]+):";
export const HEADER_START_RE = new RegExp("^" + HEADER_NAMES, "i");     // start of text
export const HEADER_ANY_RE = new RegExp("^" + HEADER_NAMES, "im");      // any line
// eslint-disable-next-line no-control-regex
const CONTROL_RE = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g;
const SCHEME_RE = /^[a-zA-Z][a-zA-Z0-9+.\-]*:\/\//;
const HOST_RE = /^[a-z0-9._\-]+$/;

// ---- input handling ------------------------------------------------------
export function sanitizeInput(raw, maxLen = MAX_TEXT_LENGTH) {
  if (typeof raw !== "string") throw new InvalidInput("Please enter a URL, email address or file hash.");
  const cleaned = raw.replace(CONTROL_RE, "").trim();
  if (!cleaned) throw new InvalidInput("Please enter a URL, email address or file hash.");
  if (cleaned.length > maxLen) throw new InvalidInput(`Input is too long (maximum ${maxLen} characters).`);
  return cleaned;
}

export function detectInputType(value) {
  if (HASH_RE.test(value)) return "hash";
  if (value.includes("\n") || value.includes("\r") || HEADER_START_RE.test(value)) return "email_message";
  if (EMAIL_ADDR_RE.test(value)) return "email_address";
  if (/\s/.test(value)) return "email_message";
  return "url";
}

// ---- domain helpers ------------------------------------------------------
export function splitHost(host) {
  const labels = host.split(".");
  const keep = labels.length >= 3 && labels[labels.length - 1].length === 2 &&
    SECOND_LEVEL.has(labels[labels.length - 2]) ? 3 : 2;
  if (labels.length <= keep) return [[], host];
  return [labels.slice(0, -keep), labels.slice(-keep).join(".")];
}

export function registeredDomain(host) {
  return splitHost(host.toLowerCase().replace(/^\.+|\.+$/g, ""))[1];
}

export function isIpAddress(host) {
  return isIP(host.replace(/^\[|\]$/g, "")) !== 0;
}

export function findBrands(text, regDomain) {
  text = text.toLowerCase();
  const mainLabel = regDomain.split(".")[0];
  return Object.entries(BRANDS)
    .filter(([brand, extra]) => text.includes(brand) && mainLabel !== brand && !extra.includes(regDomain))
    .map(([brand]) => brand);
}

// ---- signals -------------------------------------------------------------
export function makeSignal(id, triggered, weight, badTitle, badDetail, goodTitle, goodDetail) {
  const severity = triggered ? (weight >= 20 ? "bad" : "warn") : "good";
  return {
    id,
    title: triggered ? badTitle : goodTitle,
    detail: triggered ? badDetail : goodDetail,
    severity,
    triggered: !!triggered,
    weight: triggered ? weight : 0,
  };
}

function quoted(items, limit = 4) {
  let shown = items.slice(0, limit).map((i) => `"${i}"`).join(", ");
  if (items.length > limit) shown += ` +${items.length - limit} more`;
  return shown;
}

export function verdictFor(score) {
  if (score <= SAFE_MAX) return "Safe";
  if (score <= SUSPICIOUS_MAX) return "Suspicious";
  return "Phishing";
}

export function analyzeUrl(raw) {
  const url = (raw || "").trim();
  if (!url) throw new InvalidInput("Please enter a URL.");
  if (url.length > MAX_URL_LENGTH) throw new InvalidInput(`URL is too long (maximum ${MAX_URL_LENGTH} characters).`);

  const schemeMissing = !SCHEME_RE.test(url);
  const target = schemeMissing ? "https://" + url : url;
  let parts;
  try { parts = new URL(target); } catch { throw new InvalidInput("That does not look like a valid URL."); }

  const scheme = parts.protocol.replace(":", "").toLowerCase();
  if (!["http", "https", "ftp"].includes(scheme)) throw new InvalidInput("Only http, https and ftp links can be analysed.");

  const host = parts.hostname.toLowerCase().replace(/\.$/, "");
  const hostIsIp = host ? isIpAddress(host) : false;
  if (!host || (!hostIsIp && (!HOST_RE.test(host) || !host.includes(".")))) {
    throw new InvalidInput("That does not look like a valid URL.");
  }

  const netlocMatch = target.match(/^[a-zA-Z][a-zA-Z0-9+.\-]*:\/\/([^/?#]*)/);
  const netloc = netlocMatch ? netlocMatch[1] : "";
  const pathAndQuery = (parts.pathname || "") + (parts.search || "");
  const [subLabels, regDomain] = hostIsIp ? [[], host] : splitHost(host);
  const tld = hostIsIp ? "" : host.split(".").pop();
  const signals = [];

  // 1. Suspicious keywords
  const haystack = (host + pathAndQuery).toLowerCase();
  const found = SUSPICIOUS_KEYWORDS.filter((k) => haystack.includes(k));
  const kwWeight = found.length ? Math.min(28, 12 + 4 * (found.length - 1)) : 0;
  signals.push(makeSignal("keywords", found.length > 0, kwWeight,
    "Suspicious keyword", "Contains " + quoted(found),
    "No suspicious keywords", "No phishing-style words in the link"));

  // 2. Uncommon / abused TLD
  signals.push(makeSignal("tld", SUSPICIOUS_TLDS.has(tld), 20,
    "Uncommon TLD", `Uses .${tld} domain, often abused`,
    "Common TLD", "Domain ending is not on the abused list"));

  // 3. No HTTPS
  signals.push(makeSignal("no_https", scheme !== "https" && !schemeMissing, 10,
    "No HTTPS", "Connection is not encrypted",
    "HTTPS or unspecified", "No plain-HTTP link detected"));

  // 4. Long subdomain chain
  signals.push(makeSignal("subdomains", subLabels.length >= 3, 15,
    "Long subdomain chain", `${subLabels.length} subdomain levels detected`,
    "Normal subdomain depth", `${subLabels.length} subdomain level(s)`));

  // 5. Brand impersonation
  const brands = hostIsIp ? [] : findBrands(host, regDomain);
  signals.push(makeSignal("brand", brands.length > 0, 25,
    "Brand impersonation", `Mimics ${quoted(brands)} in hostname`,
    "No brand impersonation", "No well-known brand faked in the hostname"));

  // 6. Raw IP
  signals.push(makeSignal("raw_ip", hostIsIp, 30,
    "Raw IP address", "Uses an IP address instead of a domain name",
    "Not an IP address", "Uses a domain name, not raw IP"));

  // 7. '@' symbol
  signals.push(makeSignal("at_symbol", netloc.includes("@"), 15,
    "'@' symbol in URL", "Text before '@' can hide the real destination",
    "No '@' symbol", "No hidden-destination trick"));

  // 8. Very long URL
  signals.push(makeSignal("long_url", url.length > 75, 10,
    "Very long URL", `${url.length} characters long`,
    "Reasonable length", `${url.length} characters`));

  // 9. Excessive hyphens
  const hyphens = (host.match(/-/g) || []).length;
  signals.push(makeSignal("hyphens", hyphens >= 3, 10,
    "Excessive hyphens", `${hyphens} hyphens in the hostname`,
    "Few hyphens", `${hyphens} hyphen(s) in the hostname`));

  // 10. Excessive digits
  const digits = hostIsIp ? 0 : (host.match(/[0-9]/g) || []).length;
  signals.push(makeSignal("digits", digits >= 4, 8,
    "Many digits", `${digits} digits in the hostname`,
    "Few digits", `${digits} digit(s) in the hostname`));

  // 11. URL shortener
  signals.push(makeSignal("shortener", URL_SHORTENERS.has(regDomain), 30,
    "URL shortener", "Hides the real destination behind a short link",
    "Not a shortener", "Link shows its real domain"));

  // 12. Punycode / non-ASCII hostname (the URL parser converts Unicode to xn--)
  // eslint-disable-next-line no-control-regex
  const idn = host.includes("xn--") || /[^\x00-\x7f]/.test(netloc);
  signals.push(makeSignal("idn", idn, 15,
    "Look-alike characters", "Hostname uses punycode / non-ASCII characters",
    "Plain ASCII hostname", "No look-alike characters"));

  const score = Math.min(100, signals.reduce((a, s) => a + s.weight, 0));
  signals.sort((a, b) => (Number(!a.triggered) - Number(!b.triggered)) || (b.weight - a.weight));

  return {
    normalized_url: target, hostname: host, registered_domain: regDomain,
    scheme_missing: schemeMissing, signals, score, verdict: verdictFor(score),
  };
}

// ---- VirusTotal integration helpers --------------------------------------
export function vtScore(vt) {
  if (!vt) return 0;
  const mal = vt.malicious || 0, sus = vt.suspicious || 0;
  if (mal >= 5) return 95;
  if (mal >= 3) return 85;
  if (mal === 2) return 60;
  if (mal === 1) return 45;
  if (sus >= 3) return 50;
  if (sus >= 1) return 35;
  return 0;
}

export function combineScores(heuristicScore, vt) {
  if (!vt || vt.status === "pending") return Math.trunc(heuristicScore);
  const implied = vtScore(vt);
  if (implied > 0) return Math.max(heuristicScore, implied);
  if ((vt.total || 0) >= 10) return Math.round(heuristicScore * 0.8);
  return Math.trunc(heuristicScore);
}

export function vtSignal(vt) {
  if (!vt) return null;
  if (vt.status === "pending") {
    return { id: "virustotal", severity: "info", triggered: false, weight: 0,
      title: "VirusTotal analysis pending",
      detail: "Submitted for scanning. Scan again in a minute for engine results" };
  }
  const { malicious: mal = 0, suspicious: sus = 0, harmless = 0, total = 0 } = vt;
  if (mal > 0 || sus > 0) {
    return { id: "virustotal", triggered: true, weight: vtScore(vt),
      severity: mal >= 3 ? "bad" : "warn", title: "VirusTotal detections",
      detail: `${mal} malicious, ${sus} suspicious, ${harmless} harmless (of ${total} engines)` };
  }
  return { id: "virustotal", severity: "good", triggered: false, weight: 0,
    title: "VirusTotal: no detections", detail: `${harmless} harmless out of ${total} engines` };
}
