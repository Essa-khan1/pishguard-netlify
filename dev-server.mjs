// Tiny local server: serves /public and routes /api/* to the same function code
// that Netlify runs. Use:  npm start   (then open http://127.0.0.1:8888)
import http from "node:http";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import api from "./netlify/functions/api.js";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "public");
const port = parseInt(process.env.PORT || "8888", 10);
const types = { ".html": "text/html; charset=utf-8", ".css": "text/css", ".js": "text/javascript", ".png": "image/png", ".svg": "image/svg+xml", ".ico": "image/x-icon" };

http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, "http://localhost");
    if (url.pathname.startsWith("/api/")) {
      const chunks = [];
      for await (const c of req) chunks.push(c);
      const body = ["GET", "HEAD"].includes(req.method) ? undefined : Buffer.concat(chunks);
      const r = await api(new Request(url, { method: req.method, headers: req.headers, body }), { ip: req.socket.remoteAddress });
      res.writeHead(r.status, Object.fromEntries(r.headers));
      return res.end(Buffer.from(await r.arrayBuffer()));
    }
    const rel = url.pathname === "/" ? "index.html" : decodeURIComponent(url.pathname).replace(/^\/+/, "");
    const file = path.join(root, rel);
    if (!file.startsWith(root + path.sep)) { res.writeHead(403); return res.end("Forbidden"); }
    const data = await readFile(file);
    res.writeHead(200, { "content-type": types[path.extname(file)] || "application/octet-stream" });
    res.end(data);
  } catch {
    res.writeHead(404); res.end("Not found");
  }
}).listen(port, "127.0.0.1", () => console.log(`PishGuard running at http://127.0.0.1:${port}`));
