// Email analysis for PishGuard: header checks and link extraction.
// Works on pasted text only (headers and/or body). Nothing is fetched.
import { HEADER_ANY_RE, SUSPICIOUS_TLDS, findBrands, makeSignal, registeredDomain } from "./heuristics.js";

export const MAX_LINKS = 10;
const LINK_RE = /(?:https?:\/\/|www\.)[^\s<>"'\)\]\}]+/gi;
const AUTH_FAIL_RE = /\b(spf|dkim|dmarc)\s*=\s*(fail|softfail|none)\b/gi;

export function extractLinks(text, limit = MAX_LINKS) {
  const links = [];
  for (const m of text.matchAll(LINK_RE)) {
    let link = m[0].replace(/[.,;:!?>]+$/, "");
    if (link.toLowerCase().startsWith("www.")) link = "https://" + link;
    if (!links.includes(link)) links.push(link);
    if (links.length >= limit) break;
  }
  return links;
}

// ---- tiny RFC 822 parser (headers, folding, simple MIME decoding) ----------
function parseHeaders(block) {
  const headers = {};
  let current = null;
  for (const line of block.split(/\r?\n/)) {
    if (/^[ \t]/.test(line) && current) { headers[current] += " " + line.trim(); continue; }
    const m = line.match(/^([^:\s]+):\s*(.*)$/);
    if (m) {
      current = m[1].toLowerCase();
      if (!(current in headers)) headers[current] = m[2];
      else current = "\0skip";            // keep the first occurrence only
      if (current === "\0skip") headers[current] = "";
    }
  }
  delete headers["\0skip"];
  return headers;
}

function splitMessage(text) {
  const m = text.match(/\r?\n\r?\n/);
  if (!m) return [text, ""];
  return [text.slice(0, m.index), text.slice(m.index + m[0].length)];
}

function decodeBody(body, encoding) {
  encoding = (encoding || "").toLowerCase().trim();
  try {
    if (encoding === "base64") return Buffer.from(body.replace(/\s+/g, ""), "base64").toString("utf8");
    if (encoding === "quoted-printable") {
      const bytes = body.replace(/=\r?\n/g, "").replace(/=([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
      return Buffer.from(bytes, "latin1").toString("utf8");
    }
  } catch { /* fall through */ }
  return body;
}

function collectText(headers, body, depth = 0) {
  const ctype = headers["content-type"] || "text/plain";
  const boundary = ctype.match(/boundary="?([^";]+)"?/i);
  if (/^multipart\//i.test(ctype) && boundary && depth < 4) {
    const out = [];
    for (const piece of body.split("--" + boundary[1])) {
      const [h, b] = splitMessage(piece.replace(/^\r?\n/, ""));
      if (!h.trim()) continue;
      out.push(collectText(parseHeaders(h), b, depth + 1));
    }
    return out.join("\n");
  }
  if (/^text\//i.test(ctype)) return decodeBody(body, headers["content-transfer-encoding"]);
  return "";
}

export function parseAddr(value) {
  value = String(value || "");
  const angle = value.match(/^(.*?)<([^>]*)>/);
  if (angle) return { name: angle[1].trim().replace(/^"|"$/g, ""), addr: angle[2].trim() };
  const bare = value.match(/[^\s<>,;"]+@[^\s<>,;"]+/);
  return { name: "", addr: bare ? bare[0] : "" };
}

const domainOf = (address) => (address.includes("@") ? address.split("@").pop().toLowerCase().replace(/>/g, "") : "");

function parse(text) {
  if (!HEADER_ANY_RE.test(text)) return [null, text];
  const [headBlock, bodyBlock] = splitMessage(text);
  const headers = parseHeaders(headBlock);
  // A paste that is only headers has no blank-line separated body.
  const body = collectText(headers, bodyBlock);
  return [headers, body];
}

export function analyzeEmail(text) {
  const [headers, body] = parse(text);
  let links = extractLinks(body);
  if (headers && !links.length) links = extractLinks(text);   // e.g. List-Unsubscribe in headers only

  const result = { from: "", subject: "", signals: [], header_score: 0, links };
  if (!headers) return result;

  const { name: displayName, addr: fromAddr } = parseAddr(headers["from"]);
  const fromDomain = domainOf(fromAddr);
  result.from = fromAddr;
  result.subject = String(headers["subject"] || "").slice(0, 200);
  if (!fromDomain) return result;

  const fromReg = registeredDomain(fromDomain);
  const signals = [];

  const replyDomain = domainOf(parseAddr(headers["reply-to"]).addr);
  signals.push(makeSignal("replyto_mismatch", !!replyDomain && registeredDomain(replyDomain) !== fromReg, 20,
    "Reply-To mismatch", `Replies go to ${replyDomain}, not ${fromReg}`,
    "Reply-To matches sender", "No different reply address"));

  const returnDomain = domainOf(parseAddr(headers["return-path"]).addr);
  signals.push(makeSignal("returnpath_mismatch", !!returnDomain && registeredDomain(returnDomain) !== fromReg, 10,
    "Return-Path mismatch", `Bounces go to ${returnDomain}, not ${fromReg}`,
    "Return-Path matches sender", "No different return address"));

  const brands = displayName ? findBrands(displayName, fromReg) : [];
  signals.push(makeSignal("display_spoof", brands.length > 0, 25,
    "Sender name spoofing", `Display name mentions "${brands[0] || ""}" but the domain is ${fromReg}`,
    "Sender name looks genuine", "No brand faked in the display name"));

  const tld = fromDomain.split(".").pop();
  signals.push(makeSignal("sender_tld", SUSPICIOUS_TLDS.has(tld), 15,
    "Uncommon sender TLD", `Sender uses a .${tld} domain`,
    "Common sender TLD", "Sender domain ending is not on the abused list"));

  const authText = (headers["authentication-results"] || "") + " " + (headers["received-spf"] || "");
  const failed = [...new Set([...authText.matchAll(AUTH_FAIL_RE)].map((m) => m[1].toUpperCase()))].sort();
  signals.push(makeSignal("auth_fail", failed.length > 0, 20,
    "Email authentication failed", `${failed.join(", ")} did not pass`,
    "No authentication failures", "No SPF/DKIM/DMARC failure recorded"));

  const linkRegs = new Set(links.map((l) => {
    const host = l.replace(/^[a-z]+:\/\//i, "").split("/")[0].split(":")[0];
    return registeredDomain(host.toLowerCase());
  }));
  signals.push(makeSignal("links_foreign", links.length > 0 && !linkRegs.has(fromReg), 8,
    "Links to other domains", `No link points to the sender's domain (${fromReg})`,
    "Links match sender", "Links are consistent with the sender"));

  result.header_score = Math.min(100, signals.reduce((a, s) => a + s.weight, 0));
  signals.sort((a, b) => (Number(!a.triggered) - Number(!b.triggered)) || (b.weight - a.weight));
  result.signals = signals;
  return result;
}
