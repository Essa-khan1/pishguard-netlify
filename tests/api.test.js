import test, { beforeEach } from "node:test";
import assert from "node:assert/strict";
import api from "../netlify/functions/api.js";
import { _resetMemory } from "../netlify/functions/lib/database.js";

beforeEach(() => { delete process.env.DATABASE_URL; delete process.env.VT_API_KEY; _resetMemory(); });
let n = 0;
const scan = (body, ip = "t" + n++) =>
  api(new Request("http://x/api/scan", { method: "POST", body: typeof body === "string" ? body : JSON.stringify(body) }), { ip });

test("URL scan works without VirusTotal and is saved", async () => {
  const r = await scan({ input: "http://secure-paypal-update.verify-account-login.tk/signin" });
  const d = await r.json();
  assert.equal(r.status, 200);
  assert.equal(d.verdict, "Phishing");
  assert.ok(d.saved);
  assert.match(d.notices[0], /VT_API_KEY/);
  const dash = await (await api(new Request("http://x/api/dashboard"), {})).json();
  assert.equal(dash.summary.total, 1);
});
test("email address and full email message", async () => {
  assert.equal((await (await scan({ input: "support@paypal-secure.tk", mode: "email" })).json()).input_type, "email");
  const d = await (await scan({ input: "From: PayPal <a@evil.tk>\nReply-To: x@other.com\nSubject: hi\n\nClick http://paypal-login.tk/x", mode: "email" })).json();
  assert.equal(d.verdict, "Phishing");
  assert.equal(d.links.length, 1);
});
test("hash without API key gives a clear error", async () => {
  const r = await scan({ input: "d41d8cd98f00b204e9800998ecf8427e" });
  assert.equal(r.status, 503);
});
test("bad input, bad JSON and oversized body", async () => {
  assert.equal((await scan({ input: "" })).status, 400);
  assert.equal((await scan("not json")).status, 400);
  assert.equal((await scan({ input: "a".repeat(70000) })).status, 413);
});
test("rate limiting kicks in", async () => {
  let last;
  for (let i = 0; i < 17; i++) last = await scan({ input: "https://example.com" }, "same-ip");
  assert.equal(last.status, 429);
});
test("database down: scan still works with a notice", async () => {
  process.env.DATABASE_URL = "postgresql://u:p@127.0.0.1:1/db?sslmode=require";
  const d = await (await scan({ input: "https://example.com" })).json();
  assert.equal(d.saved, false);
  assert.match(d.db_notice, /could not be saved/);
});
test("XSS text comes back as data, not markup", async () => {
  const d = await (await scan({ input: "From: <script>alert(1)</script> <a@b.tk>\nSubject: x\n\nhttp://x.tk" })).json();
  assert.ok(d.target.length > 0);   // front end uses textContent, never innerHTML
});
