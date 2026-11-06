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
  assert.equal(h.combineScores(50, { malicious: 0, suspicious: 0, total: 70, status: "found" }), 40);
});
test("verdict boundaries", () => {
  assert.deepEqual([0, 29, 30, 59, 60, 100].map(h.verdictFor),
    ["Safe", "Safe", "Suspicious", "Suspicious", "Phishing", "Phishing"]);
});
