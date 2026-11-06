import test, { beforeEach } from "node:test";
import assert from "node:assert/strict";
import * as db from "../netlify/functions/lib/database.js";

beforeEach(() => { delete process.env.DATABASE_URL; db._resetMemory(); });

test("falls back to memory without DATABASE_URL", () => assert.equal(db.backendName(), "memory"));
test("empty summary", async () => {
  assert.deepEqual(await db.getSummary(), { phishing: 0, suspicious: 0, safe: 0, total: 0 });
});
test("save and read back, newest first", async () => {
  await db.saveScan("http://x.tk", "url", "Phishing", 87, 80, { malicious: 3 }, [{ id: "a" }]);
  await db.saveScan("https://github.com", "url", "Safe", 3);
  const s = await db.getSummary();
  assert.deepEqual([s.phishing, s.safe, s.total], [1, 1, 2]);
  assert.equal((await db.getRecent(5))[0].input_value, "https://github.com");
});
test("hostile text is stored literally", async () => {
  const evil = "x'); DROP TABLE scans;--";
  await db.saveScan(evil, "url", "Safe", 1);
  assert.equal((await db.getRecent(1))[0].input_value, evil);
});
test("unreachable Postgres becomes DatabaseError", async () => {
  process.env.DATABASE_URL = "postgresql://u:p@127.0.0.1:1/db?sslmode=require";
  await assert.rejects(db.getSummary(), db.DatabaseError);
  process.env.DATABASE_URL = "not-a-url";
  await assert.rejects(db.getRecent(), db.DatabaseError);
});
