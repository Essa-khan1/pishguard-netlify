# PishGuard (Netlify edition)

Phishing & Malicious URL Scanner. Detection is **rule-based (heuristics) plus VirusTotal**. PishGuard never visits a scanned link; it only analyses the text and asks VirusTotal.

Scans a **URL**, an **email** (address or a whole pasted message) or a **file hash**.

## Project layout
```
PishGuard-Netlify/
├── netlify.toml                      Netlify settings
├── package.json                      one dependency: @neondatabase/serverless
├── dev-server.mjs                    local server (npm start)
├── .env.example  .gitignore
├── public/                           the website
│   ├── index.html  style.css  app.js
├── netlify/functions/
│   ├── api.js                        the backend (/api/scan, /api/dashboard)
│   └── lib/ heuristics.js  virustotal.js  emailAnalyzer.js  database.js
└── tests/                            npm test
```

## Run locally (Windows)
1. Install **Node.js 20 or newer** (LTS) from nodejs.org.
2. Open PowerShell in the PishGuard-Netlify folder:
   ```
   npm install
   copy .env.example .env
   ```
3. Edit `.env` in Notepad:
   - `VT_API_KEY=` your free VirusTotal key (virustotal.com -> sign up -> profile -> **API Key**). Free tier = 4 requests/minute.
   - `DATABASE_URL=` your Neon connection string (see below). Leave it empty to keep history in memory only (it resets when the server restarts).
4. `npm start` then open **http://127.0.0.1:8888**
5. Run the tests: `npm test`

## Free Neon database
1. Sign up at neon.tech and create a project.
2. Click **Connect**, copy the connection string (it ends with `?sslmode=require`).
3. Paste it as `DATABASE_URL`. The `scans` table is created automatically on first use.

## Deploy to Netlify
1. Push to GitHub:
   ```
   git init
   git add .
   git commit -m "PishGuard"
   git branch -M main
   git remote add origin https://github.com/YOUR-USER/pishguard.git
   git push -u origin main
   ```
   (`.env` is git-ignored, so your keys are never uploaded.)
2. On app.netlify.com choose **Add new site -> Import an existing project -> GitHub** and pick the repo. Leave the build command empty; `netlify.toml` already sets the publish folder and functions folder.
3. Before deploying, open **Site configuration -> Environment variables** and add `VT_API_KEY` and `DATABASE_URL`.
4. Click **Deploy**. Your site gets a `*.netlify.app` address.

Use the GitHub import above. Drag-and-drop deploys do not build the serverless function.

## Notes
- **Timeout:** Netlify functions on the free plan stop after about 10 seconds. If VirusTotal has never seen a URL, PishGuard submits it and waits a few seconds; if the result is not ready it shows "VirusTotal analysis pending" and the heuristic score. Scan again a minute later for engine results.
- **Rate limiting** is per IP, in memory per function instance (a basic safeguard, not a hard guarantee on serverless).
- **Security:** input is sanitized and length-limited, output is inserted as plain text (no XSS), SQL is parameterized, secrets live in environment variables.
