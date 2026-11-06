import test from "node:test";
import assert from "node:assert/strict";
import * as h from "../netlify/functions/lib/heuristics.js";
 
const triggered = (r) => new Set(r.signals.filter((s) => s.triggered).map((s) => s.id));
 
test("phishing URL is flagged", () => {
  const r = h.analyzeUrl("http://secure-paypal-update.verify-account-login.tk/signin");
  assert.equal(r.verdict, "Phishing");
  for (const id of ["keywords", "tld", "no_https", "brand"]) assert.ok(triggered(r).has(id), id);
});
test("safe URL stays safe", () => {
  const r = h.analyzeUrl("https://github.com/anthropics");
  assert.equal(r.verdict, "Safe");
  assert.ok(r.score < 30);
});
test("official brand domain is not impersonation", () => {
  assert.ok(!triggered(h.analyzeUrl("https://accounts.google.com")).has("brand"));
});
test("raw IP, shortener and @ trick", () => {
  assert.ok(triggered(h.analyzeUrl("http://192.168.44.21/login.php")).has("raw_ip"));
  assert.ok(triggered(h.analyzeUrl("https://bit.ly/abc")).has("shortener"));
  assert.ok(triggered(h.analyzeUrl("http://google.com@evil.example/x")).has("at_symbol"));
});
test("invalid input is rejected", () => {
  for (const bad of ["", "javascript:alert(1)", "nodots"]) assert.throws(() => h.analyzeUrl(bad), h.InvalidInput);
});
test("input type detection", () => {
  assert.equal(h.detectInputType("d41d8cd98f00b204e9800998ecf8427e"), "hash");
  assert.equal(h.detectInputType("a@b.com"), "email_address");
  assert.equal(h.detectInputType("https://x.com"), "url");
  assert.equal(h.detectInputType("From: a@b.com\nSubject: hi"), "email_message");
});
test("sanitize", () => {
  assert.equal(h.sanitizeInput("  a\x00b "), "ab");
  assert.throws(() => h.sanitizeInput("x".repeat(30000)), h.InvalidInput);
});
test("combine scores with VirusTotal", () => {
  assert.equal(h.combineScores(40, null), 40);
  assert.equal(h.combineScores(10, { malicious: 6, suspicious: 0, total: 70 }), 95);
  const clean = { malicious: 0, suspicious: 0, total: 70, status: "found" };
  assert.equal(h.combineScores(20, clean), 16);   // clean result trims a low score
  assert.equal(h.combineScores(50, clean), 50);   // but never lowers a Suspicious one
});
test("verdict boundaries", () => {
  assert.deepEqual([0, 29, 30, 59, 60, 100].map(h.verdictFor),
    ["Safe", "Safe", "Suspicious", "Suspicious", "Phishing", "Phishing"]);
});
 
test("look-alike brand spellings are caught", () => {
  for (const u of ["https://paypa1.com", "https://g00gle-support.com", "https://faceb00k.com",
                   "https://arnazon.com", "https://paypai.com", "https://micr0soft-login.com"]) {
    assert.ok(triggered(h.analyzeUrl(u)).has("lookalike"), u);
    assert.notEqual(h.analyzeUrl(u).verdict, "Safe", u);
  }
});
test("real brand sites and ordinary words are not look-alikes", () => {
  for (const u of ["https://www.paypal.com", "https://accounts.google.com", "https://github.com",
                   "https://www.amazon.com", "https://learn.example.org", "https://example.com"]) {
    assert.ok(!triggered(h.analyzeUrl(u)).has("lookalike"), u);
    assert.equal(h.analyzeUrl(u).verdict, "Safe", u);
  }
});
test("brand name on a foreign domain is at least Suspicious", () => {
  assert.notEqual(h.analyzeUrl("https://amazon-gift.com/claim").verdict, "Safe");
  assert.equal(h.analyzeUrl("https://www.paypal.com.account-verify.net").verdict, "Phishing");
});