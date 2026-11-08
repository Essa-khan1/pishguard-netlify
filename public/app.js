"use strict";
// All dynamic text is inserted with textContent (never innerHTML) to prevent XSS.
function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined && text !== null) e.textContent = text;
  return e;
}
const $ = (id) => document.getElementById(id);

// Anonymous per-browser ID: keeps each visitor's history separate and private.
function makeId() {
  if (window.crypto && crypto.randomUUID) return crypto.randomUUID();
  return "id-" + Math.random().toString(16).slice(2) + Date.now().toString(16) + Math.random().toString(16).slice(2);
}
let clientId;
try { clientId = localStorage.getItem("pishguard_client"); } catch (e) { clientId = null; }
if (!clientId || clientId.length < 16) {
  clientId = makeId();
  try { localStorage.setItem("pishguard_client", clientId); } catch (e) { /* private mode: lasts for this visit */ }
}
const authHeaders = (extra) => Object.assign({ "X-Client-Id": clientId }, extra || {});

function note(msg, isErr) { $("notices").appendChild(el("div", "note" + (isErr ? " err" : ""), msg)); }
function pill(v) { return el("span", "pill " + v, v); }

async function loadDashboard() {
  try {
    const r = await fetch("/api/dashboard", { headers: authHeaders() });
    const d = await r.json();
    $("dbNotice").textContent = "";
    if (!d.db_ok) {
      $("dbNotice").appendChild(el("div", "note", "History is unavailable (database not reachable)."));
      return;
    }
    if (d.storage === "memory") {
      $("dbNotice").appendChild(el("div", "note", "No database connected: history is temporary. Add DATABASE_URL to keep it."));
    }
    $("sPhishing").textContent = d.summary.phishing;
    $("sSuspicious").textContent = d.summary.suspicious;
    $("sSafe").textContent = d.summary.safe;
    $("sTotal").textContent = d.summary.total;
    const body = $("recent");
    body.textContent = "";
    if (!d.recent.length) {
      const tr = el("tr"); const td = el("td", "muted", "No scans yet"); td.colSpan = 3;
      tr.appendChild(td); body.appendChild(tr); return;
    }
    d.recent.forEach((s) => {
      const tr = el("tr");
      const u = el("td", null, s.input_value); u.title = s.input_value;
      const v = el("td"); v.appendChild(pill(s.verdict));
      tr.append(u, v, el("td", null, s.risk_score + "%"));
      body.appendChild(tr);
    });
  } catch (e) {
    $("dbNotice").appendChild(el("div", "note", "Could not load history."));
  }
}

function render(d) {
  const res = $("result"); res.textContent = "";
  const box = el("div", "verdict " + d.verdict);
  const ring = el("div", "ring", d.risk_score + "%");
  ring.style.setProperty("--p", d.risk_score);
  const info = el("div");
  const icon = d.verdict === "Safe" ? "✔ SAFE" : d.verdict === "Suspicious" ? "⚠ SUSPICIOUS" : "⚠ PHISHING DETECTED";
  const level = d.verdict === "Safe" ? "Low Risk" : d.verdict === "Suspicious" ? "Medium Risk" : "High Risk";
  info.appendChild(el("h4", null, icon + " — " + level));
  let line = "Risk score: " + d.risk_score + "%";
  if (d.vt) line += " · VirusTotal: " + d.vt.malicious + " malicious, " + d.vt.suspicious + " suspicious, " + d.vt.harmless + " harmless";
  info.appendChild(el("p", null, line));
  info.appendChild(el("p", "mono", d.target));
  box.append(ring, info);
  res.appendChild(box);

  const sig = $("signals"); sig.textContent = "";
  d.signals.forEach((s) => {
    const c = el("div", "sig " + (s.severity || "info"));
    c.append(el("b", null, s.title), el("span", null, s.detail));
    sig.appendChild(c);
  });
  const links = $("links"); links.textContent = "";
  if (d.links && d.links.length) {
    links.appendChild(el("h3", null, "Links found in the email"));
    d.links.forEach((l) => {
      const row = el("div", "linkrow");
      const code = el("code", null, l.url); code.title = l.url;
      row.append(pill(l.verdict), el("span", null, l.risk_score + "%"), code);
      links.appendChild(row);
    });
  }
  $("whyWrap").hidden = false;
  (d.notices || []).forEach((n) => note(n));
  if (d.db_notice) note(d.db_notice);
}

const MODES = {
  url:   {title: "Scan a URL", hint: "Paste a link to check it for phishing indicators",
          ph: "https://example.com/login", rows: 1},
  email: {title: "Scan an Email", hint: "Paste a sender address, or the full email (headers and body) to check the sender and every link inside",
          ph: "support@example.com\n\u2014 or paste the whole email here \u2014", rows: 8},
  hash:  {title: "Scan a File Hash", hint: "Paste an MD5, SHA-1 or SHA-256 hash to look it up on VirusTotal (no file is uploaded)",
          ph: "d41d8cd98f00b204e9800998ecf8427e", rows: 1},
};
let mode = "url";
document.querySelectorAll(".tab").forEach((t) => t.addEventListener("click", () => {
  mode = t.dataset.mode;
  document.querySelectorAll(".tab").forEach((x) => x.classList.toggle("active", x === t));
  const m = MODES[mode];
  $("scanTitle").textContent = m.title;
  $("scanHint").textContent = m.hint;
  $("scanInput").placeholder = m.ph;
  $("scanInput").rows = m.rows;
  $("notices").textContent = "";
}));

$("scanForm").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const btn = $("scanBtn");
  const value = $("scanInput").value;
  $("notices").textContent = "";
  const trimmed = value.trim();
  if (mode === "hash" && !/^([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/i.test(trimmed)) {
    note("That is not a valid MD5, SHA-1 or SHA-256 hash.", true); return;
  }
  if (mode === "email" && !trimmed.includes("@") && !/https?:\/\/|www\./i.test(trimmed)) {
    note("Paste an email address or the full email text.", true); return;
  }
  if (mode === "url" && /\s/.test(trimmed)) {
    note("A URL cannot contain spaces. Use the Email tab to scan a whole message.", true); return;
  }
  btn.disabled = true; btn.textContent = "Scanning…";
  try {
    const r = await fetch("/api/scan", {
      method: "POST", headers: authHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({ input: value, mode: mode }),
    });
    const d = await r.json();
    if (!r.ok) { $("result").textContent = ""; $("whyWrap").hidden = true; note(d.error || "Scan failed.", true); }
    else { render(d); loadDashboard(); }
  } catch (e) {
    note("Could not reach the server.", true);
  } finally {
    btn.disabled = false; btn.textContent = "Scan Now";
  }
});
loadDashboard();

$("clearBtn").addEventListener("click", async () => {
  if (!confirm("Delete your scan history? This cannot be undone.")) return;
  try {
    const r = await fetch("/api/clear", { method: "POST", headers: authHeaders() });
    if (!r.ok) { const d = await r.json(); note(d.error || "Could not clear history.", true); return; }
    $("result").textContent = ""; $("whyWrap").hidden = true;
  } catch (e) {
    note("Could not reach the server.", true); return;
  }
  loadDashboard();
});