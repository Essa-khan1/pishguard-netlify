import test, { afterEach, beforeEach } from "node:test";
import assert from "node:assert/strict";
import * as vt from "../netlify/functions/lib/virustotal.js";
import { analyzeEmail } from "../netlify/functions/lib/emailAnalyzer.js";

const realFetch = globalThis.fetch;
const res = (status, body) => new Response(JSON.stringify(body), { status });
beforeEach(() => { process.env.VT_API_KEY = "k"; process.env.VT_POLL_INTERVAL = "0"; });
afterEach(() => { globalThis.fetch = realFetch; delete process.env.VT_API_KEY; });

test("url id is unpadded base64url", () => assert.equal(vt.urlId("http://a.b/?x=1>"), "aHR0cDovL2EuYi8_eD0xPg"));
test("known URL returns engine counts", async () => {
  globalThis.fetch = async () => res(200, { data: { attributes: { last_analysis_stats: { malicious: 4, suspicious: 1, harmless: 60, undetected: 10 } } } });
  const r = await vt.checkUrl("http://x.tk");
  assert.deepEqual([r.malicious, r.suspicious, r.harmless, r.total, r.status], [4, 1, 60, 75, "found"]);
});
test("unknown URL is submitted and polled", async () => {
  const calls = [];
  globalThis.fetch = async (u, o) => {
    calls.push(o.method + " " + new URL(u).pathname.split("/")[3]);
    if (o.method === "GET" && u.includes("/urls/")) return res(404, {});
    if (o.method === "POST") return res(200, { data: { id: "an1" } });
    return res(200, { data: { attributes: { status: "completed", stats: { malicious: 0, harmless: 70, suspicious: 0, undetected: 5 } } } });
  };
  const r = await vt.checkUrl("http://new.example");
  assert.equal(r.status, "submitted");
  assert.deepEqual(calls, ["GET urls", "POST urls", "GET analyses"]);
});
test("never-finishing analysis is reported as pending", async () => {
  globalThis.fetch = async (u, o) => o.method === "POST" ? res(200, { data: { id: "a" } })
    : u.includes("/urls/") ? res(404, {}) : res(200, { data: { attributes: { status: "queued" } } });
  assert.equal((await vt.checkUrl("http://new.example")).status, "pending");
});
test("429 gives the friendly rate-limit error; bad key; missing key", async () => {
  globalThis.fetch = async () => res(429, {});
  await assert.rejects(vt.checkUrl("http://a.b"), vt.VTRateLimited);
  globalThis.fetch = async () => res(401, {});
  await assert.rejects(vt.checkHash("d41d8cd98f00b204e9800998ecf8427e"), /API key/);
  delete process.env.VT_API_KEY;
  await assert.rejects(vt.checkDomain("a.com"), vt.VTNotConfigured);
});
test("unknown hash returns null", async () => {
  globalThis.fetch = async () => res(404, {});
  assert.equal(await vt.checkHash("d41d8cd98f00b204e9800998ecf8427e"), null);
});

test("MIME email: quoted-printable body, folded headers, auth failure", () => {
  const mail = [
    "From: \"PayPal Support\" <service@paypa1-mail.tk>", "Reply-To: help@other.com",
    "Authentication-Results: mx; spf=fail smtp.mailfrom=x;",
    "  dkim=none", "Subject: Verify",
    "Content-Type: text/html", "Content-Transfer-Encoding: quoted-printable", "",
    "<a href=3D\"http://paypal-verify.tk/login\">Click</a>",
  ].join("\r\n");
  const r = analyzeEmail(mail);
  assert.equal(r.from, "service@paypa1-mail.tk");
  assert.deepEqual(r.links, ["http://paypal-verify.tk/login"]);
  const ids = r.signals.filter((s) => s.triggered).map((s) => s.id);
  for (const id of ["replyto_mismatch", "display_spoof", "sender_tld", "auth_fail", "links_foreign"]) assert.ok(ids.includes(id), id);
});
