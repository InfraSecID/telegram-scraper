# Telegram Scraper

REST API and Telegram bot for scraping websites. Scraping sources are defined in YAML files, so you can add or change targets without modifying the code.

- **API**: Express (`/api/...`) with API keys, rate limiting, a job queue, and JSON/CSV results.
- **Bot**: Telegraf — source listings, scrape buttons, automatic notifications, file delivery, and a bug bounty menu.
- **Security**: XSS/SQLi/CVE/misconfiguration scans with httpx, nuclei, katana, paramspider, dalfox, sqlmap, and subfinder, plus automatic Markdown/JSON reports (allowlisted scope and authorization confirmation).
- **Engine**: cheerio, pagination (`{page}` or a "next" button), field extraction and transforms, detail-page enrichment, deduplication, and `robots.txt` compliance.
- **Storage**: SQLite for jobs, results, security scans, findings, and reports; no Redis or external database required.
- **Deployment**: Docker Compose, polling or webhook, and automatic HTTPS (Caddy).

```
┌──────────────┐   HTTP + API key   ┌───────────────────────────┐
│ Client/curl  │ ─────────────────▶ │ Express API               │
└──────────────┘                    │  ├─ job queue (in-process)│
                                    │  ├─ scraper engine ───────┼──▶ Website
┌──────────────┐   long polling /   │  ├─ SQLite (jobs/results) │
│ Telegram     │ ◀────────────────▶ │  └─ Telegraf bot          │
└──────────────┘   webhook          └───────────────────────────┘
```

---

## 1. Quick start (local)

Prerequisite: **Node.js 22+**.

```bash
cd telegram-scraper
npm install
cp .env.example .env
# Edit .env — minimum: TELEGRAM_BOT_TOKEN, TELEGRAM_ALLOWED_USER_IDS, API_KEY
npm run dev
```

Check the API:

```bash
curl http://localhost:3000/healthz
```

### Create a bot token

1. Chat with [@BotFather](https://t.me/BotFather) → `/newbot` → follow the instructions → copy the token.
2. Set `TELEGRAM_BOT_TOKEN` in `.env`.
3. Open your bot and send any message. Since you are not allowlisted yet, the bot will reply with your **Telegram ID**.
4. Add that ID to `TELEGRAM_ALLOWED_USER_IDS` (multiple IDs are allowed; separate them with commas).
5. Restart the app (`npm run dev`).

### Create an API key

```bash
openssl rand -hex 32
```

Copy the output into `API_KEY`.

---

## 2. Bot commands

| Command | Description |
| --- | --- |
| `/start` | Main menu |
| `/menu` | All menus (scraper, jobs, bug bounty) |
| `/sources` | List sources and show scrape buttons |
| `/scrape <id> [limit] [pages]` | Start a job, e.g. `/scrape books-demo 20 2` |
| `/jobs` | Show the 10 most recent jobs |
| `/job <id>` | Show job details, metadata, and warnings |
| `/results <id> [json\|csv]` | Send results as a file |
| `/bugbounty` | Open the security / bug bounty menu |
| `/scan <url> [quick\|standard\|deep]` | Scan for XSS, SQLi, CVEs, etc. (confirmation required) |
| `/retry <scan-id>` | Create a new scan from one that failed due to the overall timeout (confirmation required again) |
| `/scans` | Show the 10 most recent security scans |
| `/scaninfo <id>` | Show scan details and findings |
| `/tools` | Show security tool status |
| `/toolbox` | Open references to manual security tools |
| `/scope` | Show allowed domains |
| `/report <id> [md\|json]` | Download an automatically generated report |
| `/sendreport <id> [email]` | Send a report to the target (optional; disabled by default) |
| `/id` | Show your User ID and Chat ID |
| `/help` | Show full help |

When a job completes, the bot notifies the chat that started it and includes buttons to download the JSON/CSV results.

---

## 3. REST API

All `/api/*` endpoints require this header:

```
x-api-key: <API_KEY>
```

or `Authorization: Bearer <API_KEY>`.

| Method | Path | Description |
| --- | --- | --- |
| GET | `/healthz` | Health check (public) |
| GET | `/api/openapi.json` | OpenAPI specification (public) |
| GET | `/api/sources` | List sources and configuration errors |
| GET | `/api/sources/:id` | Get a source's full configuration |
| POST | `/api/scrape` | Run a job from a registered source |
| POST | `/api/scrape/adhoc` | Scrape an arbitrary URL with selectors (SSRF-guarded) |
| GET | `/api/jobs?limit=20&status=` | List jobs |
| GET | `/api/jobs/:id` | Get job status |
| GET | `/api/jobs/:id/results?format=json\|csv` | Get job results |
| GET | `/api/security/status` | Get security scanner status |
| POST | `/api/security/scans` | Start a scan (`confirmAuthorization: true` required) |
| GET | `/api/security/scans` | List security scans |
| GET | `/api/security/scans/:id` | Get scan details and findings |
| GET | `/api/security/scans/:id/report` | Download the generated report |
| POST | `/api/security/scans/:id/report/send` | Send a report by email |
| POST | `/api/security/scans/:id/cancel` | Cancel a scan |

### Examples

```bash
export API_KEY="your-api-key"
BASE=http://localhost:3000

curl -s -H "x-api-key: $API_KEY" "$BASE/api/sources" | jq

curl -s -X POST "$BASE/api/scrape" \
  -H "x-api-key: $API_KEY" -H "content-type: application/json" \
  -d '{"sourceId":"books-demo","limit":20,"maxPages":2}'

curl -s -H "x-api-key: $API_KEY" "$BASE/api/jobs/<job-id>" | jq

curl -s -H "x-api-key: $API_KEY" \
  "$BASE/api/jobs/<job-id>/results?format=csv" -o results.csv
```

Ad hoc (without a configuration file):

```bash
curl -s -X POST "$BASE/api/scrape/adhoc" \
  -H "x-api-key: $API_KEY" -H "content-type: application/json" \
  -d '{
    "url": "https://quotes.toscrape.com/",
    "listSelector": "div.quote",
    "limit": 5,
    "fields": {
      "quote":  { "selector": "span.text", "transforms": ["trim"] },
      "author": { "selector": "small.author" },
      "tags":   { "selector": "a.tag", "multiple": true }
    }
  }'
```

Jobs run asynchronously (`queued` → `running` → `succeeded`/`failed`). Poll `GET /api/jobs/:id` for status.

---

## 4. Security / Bug Bounty (XSS, SQLi, CVEs)

The security module adds web vulnerability scanning and **automatic report generation**. It uses popular open-source bug bounty tools: `httpx`, `nuclei`, `katana`, `paramspider`, `dalfox`, `sqlmap`, and `subfinder`.

> ⚠️ **Only scan targets that you have written permission to test** (a bug bounty program, a penetration-testing contract, or assets you own). Targets must be listed in `SECURITY_ALLOWED_DOMAINS`, and every scan requires authorization confirmation.

### 4.1 Workflow

1. Configure the scope in `.env`:
   ```dotenv
   SECURITY_ALLOWED_DOMAINS=example.com,*.example.com
   ```
2. Send `/scan https://example.com standard` to the bot (or call `POST /api/security/scans`).
3. The bot displays an **authorization confirmation** button. The scan is queued only after you press it.
4. The scan runs asynchronously. The bot sends a notification when it completes.
5. **Markdown and JSON reports are generated automatically** in `data/security/reports/<scan-id>/`.
6. Download a report with `/report <id>` or the API. To send it to the target, use `/sendreport <id> [email]` — this is disabled by default and always requires confirmation.

If the entire scan fails because it reaches `SECURITY_SCAN_TIMEOUT_MS`, run `/retry <scan-id>`. This command
accepts only scans that failed due to the overall timeout, creates a **new scan ID**, checks the scope again, and
requires fresh authorization confirmation. Cooldown limits still apply. Scans are never retried automatically.
A timeout from an individual tool is recorded as a report warning; manually start a new `/scan` if needed.
Timeout failure notifications also include a **Retry (confirm)** button.

### 4.2 Scan profiles

| Profile | Includes | Best for |
| --- | --- | --- |
| `quick` | Header/cookie checks + httpx + nuclei high/critical severity | Quick checks |
| `standard` | Quick + katana/paramspider + dalfox (XSS) + sqlmap (SQLi) | Default; recommended for most use |
| `deep` | Standard + subfinder (passive subdomain reconnaissance) | Initial mapping |

### 4.3 Tools used

| Tool | Purpose | Notes |
| --- | --- | --- |
| `httpx` (ProjectDiscovery) | Fingerprint status, title, technologies, and server | Not the Python `httpx` package |
| `nuclei` | Template-based CVEs, misconfigurations, and exposures | Only CVEs covered by installed templates; intrusive/DoS/brute-force tags are excluded |
| `katana` | Crawl endpoints and parameterized URLs | Rate limited by `SECURITY_RATE_LIMIT` |
| `paramspider` | Find parameterized URLs in the Wayback archive | May be slow for large target archives |
| `dalfox` | Detect reflected/DOM XSS | Parameterized URLs only |
| `sqlmap` | Detect SQL injection | `--level=1 --risk=1`; no data dumps or OS shell |
| `subfinder` | Passive subdomain reconnaissance | `deep` profile only; results are scope-filtered |
| built-in | Security headers, cookie flags, clickjacking, server version | Cookie values are not stored |

`/toolbox` provides manual links to Postman/Hoppscotch, CyberChef, JWT.io, NVD/CVE, MITRE CWE,
VirusTotal, Gitleaks, and TruffleHog. These are not scanner integrations: the bot does not run these tools,
send targets/tokens/files to external services, or upload artifacts. Use Gitleaks/TruffleHog only on repositories
you own; do not paste production JWTs or private data into public web services. The SQLMap integration described
above is used only for limited detection. Directory brute-forcing, Nmap port scanning, and additional exploitation
tools are not included as automated phases.

The Docker image installs all the tools above at pinned versions. For local use, install them manually and set
`SECURITY_*_BIN` if a binary name or path differs. For example:

```dotenv
SECURITY_HTTPX_BIN=/usr/local/bin/httpx
SECURITY_DALFOX_BIN=/usr/local/bin/dalfox
SECURITY_SQLMAP_BIN=/usr/local/bin/sqlmap
SECURITY_PARAMSPIDER_BIN=/usr/local/bin/paramspider
SECURITY_NUCLEI_TEMPLATES=/opt/nuclei-templates
```

CVE/CWE references in reports come from template metadata and findings matching the target; they are not a
complete inventory of historical CVEs or a version assessment of every component. Update Nuclei templates
regularly with `nuclei -update-templates`. Results remain limited to the installed templates and may include
false positives or false negatives.

Check tool readiness with `/tools` or:

```bash
curl -s -H "x-api-key: $API_KEY" "$BASE/api/security/tools?refresh=1" | jq
```

### 4.4 Automatic reports

Each successful scan produces:

- `data/security/reports/<scan-id>/report.md` — a report ready to share (summary, evidence, reproduction steps, recommendations, CWE/CVE references).
- `data/security/reports/<scan-id>/report.json` — structured data for integrations.
- `data/security/<scan-id>/` — raw tool output evidence (httpx, nuclei, dalfox, sqlmap, etc.).

Reports do not include Telegram IDs, cookie values, session tokens, or credentials. The target's
`/.well-known/security.txt` contact is also detected when available.

The Markdown report contains a severity summary, target and timestamp, methodology, and details for each
finding. Finding details include the URL/parameter, bounded evidence, CWE/CVE references when available,
verification steps, remediation recommendations, and reference links. Example:

```markdown
#### 1. Missing Content-Security-Policy
- **Severity:** Low
- **Category:** Misconfiguration
- **Tool:** headers
- **URL:** `https://example.com/`

**Evidence**
The response does not include a Content-Security-Policy header. (HTTP 200)

**Remediation**
Apply a CSP that restricts script, style, and frame sources.
```

Locations depend on the available tool evidence. For host-level findings, the report shows the target URL
instead of inventing an application file or line number.

Email delivery uses SMTP and is **disabled by default**:

```dotenv
SECURITY_REPORT_SEND=false      # Set to true only if you are authorized to contact the target
SECURITY_REPORT_TO=             # Optional default recipient
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=
SMTP_PASS=
SMTP_FROM=security@example.com
```

### 4.5 Security bot commands

| Command | Description |
| --- | --- |
| `/bugbounty` | Open the bug bounty menu |
| `/scan <url> [quick\|standard\|deep]` | Start a scan and confirm authorization |
| `/retry <scan-id>` | Retry a scan that failed due to the overall timeout as a new scan (confirmation required) |
| `/scans` | Show the 10 most recent scans |
| `/scaninfo <id>` | Show scan details and findings |
| `/tools` | Show tool and nuclei template status |
| `/toolbox` | Open manual tool references |
| `/scope` | Show allowed domains |
| `/report <id> [md\|json]` | Download a report |
| `/sendreport <id> [email]` | Send a report to the target (confirmation and SMTP required) |

### 4.6 Endpoint API security

| Method | Path | Description |
| --- | --- | --- |
| GET | `/api/security/status` | Scanner, scope, tool, and queue status |
| GET | `/api/security/tools?refresh=1` | Tool status |
| GET | `/api/security/scope` | Allowed scope |
| POST | `/api/security/scans` | Start a scan (`confirmAuthorization: true` required) |
| GET | `/api/security/scans` | List scans |
| GET | `/api/security/scans/:id` | Get scan details, findings, and report |
| GET | `/api/security/scans/:id/report?format=md\|json` | Download a report |
| POST | `/api/security/scans/:id/report/send` | Send an email (`confirmSend: true` required) |
| POST | `/api/security/scans/:id/cancel` | Cancel a scan |

Example:

```bash
curl -s -X POST "$BASE/api/security/scans" \
  -H "x-api-key: $API_KEY" -H "content-type: application/json" \
  -d '{"target":"https://example.com","profile":"standard","confirmAuthorization":true}'

curl -s -H "x-api-key: $API_KEY" "$BASE/api/security/scans/<scan-id>" | jq

curl -s -H "x-api-key: $API_KEY" \
  "$BASE/api/security/scans/<scan-id>/report?format=md" -o report.md

curl -s -X POST "$BASE/api/security/scans/<scan-id>/report/send" \
  -H "x-api-key: $API_KEY" -H "content-type: application/json" \
  -d '{"to":"security@example.com","confirmSend":true}'
```

### 4.7 Scanner limitations

- Scanning is for **detection**, not exploitation. Manually verify findings before reporting them.
- XSS/SQLi checks only cover URLs/parameters found by the crawler/paramspider; forms requiring login or extensive JavaScript may be missed.
- Nuclei templates may produce false positives or false negatives depending on the application version.
- Endpoints that block the scanner (WAF/403) reduce coverage — review the warnings in the report.
- Reports are never sent to targets automatically; human confirmation and SMTP configuration are still required.

---

## 5. Adding a scraping source

Create a `.yaml` file in `config/sources/`. Files are reloaded on every request, so **no restart is needed**.
Configuration is validated (Zod); per-file errors appear in `/sources` without preventing other sources from loading.

Complete example:

```yaml
id: sample-news                   # lowercase letters, numbers, hyphens, or underscores; must be unique
name: Sample News
description: Example news listing
enabled: true

request:
  url: https://example.com/news?page={page}    # page placeholder
  startPage: 1
  maxPages: 5
  delayMs: 1000                  # minimum delay per origin
  timeoutMs: 15000
  headers:
    referer: https://example.com/
    cookie: session=abc123       # optional, for sites that require a session
  # nextSelector: a.next         # alternative pagination using a "next" button

list:
  selector: article.news
  limit: 50                      # target number of items per job

fields:
  title:
    selector: h2 a
  url:
    selector: h2 a
    attr: href
    transforms: [absoluteUrl]
  date:
    selector: time
    attr: datetime
    transforms: [date]
  summary:
    selector: p.summary
    transforms: [collapseWhitespace]
  categories:
    selector: .category
    multiple: true
  source:
    const: example.com
  author:
    selector: .author
    transforms:
      - trim
      - { name: default, value: "Anonymous" }

dedupeKey: url                   # optional; defaults to the full item contents
maxItems: 200

# Optional: extract additional data from each item's detail page.
detail:
  enabled: true
  linkField: url
  maxItems: 10
  fields:
    content:
      selector: article.content
      transforms: [collapseWhitespace]
```

### Pagination

- `request.url` contains `{page}` → pages 1, 2, 3, … up to `maxPages` (or until a 404, empty page, or limit).
- Without `{page}`, `request.nextSelector` follows the "next" button's `href` up to `maxPages`.
- If both are present, `{page}` takes precedence.

### Field

| Property | Description |
| --- | --- |
| `selector` | CSS selector. `@` refers to the item element itself. Required unless `const` is set. |
| `const` | Fixed value; does not extract data from the page. |
| `attr` | `text` (default), `html`, `outerHtml`, or an attribute name (`href`, `data-id`, …). |
| `multiple` | Return all matching elements as an array. |
| `raw` | Do not trim text (text is trimmed by default). |
| `default` | Replacement value when the result is empty. |
| `transforms` | Ordered list of transforms (strings or objects). |

### Transform

| Name | Args | Description |
| --- | --- | --- |
| `trim` | – | Remove leading and trailing whitespace |
| `collapseWhitespace` | – | Collapse whitespace and newlines |
| `lowercase` / `uppercase` | – | Change letter case |
| `number` | – | Parse a number (`1.234,56` or `1,234.56` format) |
| `int` | – | Parse a number and remove its decimal part |
| `absoluteUrl` | – | Convert a relative URL to an absolute URL |
| `regex` | `pattern`, `flags?`, `group?` | Extract a capture group (group 0 by default) |
| `replace` | `pattern`, `flags?`, `replacement` | Replace using a regular expression |
| `prefix` / `suffix` | `value` | Add text |
| `default` | `value` | Set a value if the result is empty |
| `date` | – | Parse a date into ISO 8601 |
| `json` | – | Parse a JSON string |

Transforms run in order; an empty value can only be recovered with `default`.

**Note:** The engine respects `robots.txt` by default (`RESPECT_ROBOTS=true`) and applies the `delayMs` interval per origin. Follow each website's terms.

---

## 6. Deploy Docker

### Polling mode (easiest, no domain required)

1. Create a Telegram bot:
   - Open the verified **[@BotFather](https://t.me/BotFather)** chat.
   - Send `/newbot`, then follow the instructions to set the bot's **display name** and **username** (the username must end in `bot`).
   - BotFather will send you a secret token. Copy it; do not post it in public chats or add it to the README.
2. Copy and open the configuration:

```bash
cp .env.example .env
nano .env
```

3. Fill in the top of `.env` without quotes or spaces around `=`:

```dotenv
TELEGRAM_BOT_TOKEN=PASTE_BOTFATHER_TOKEN_HERE
TELEGRAM_ALLOWED_USER_IDS=
API_KEY=
```

Replace `TELEGRAM_BOT_TOKEN` with the token from BotFather. Leave `TELEGRAM_ALLOWED_USER_IDS` empty for now,
then generate a strong API key in the terminal with `openssl rand -hex 32` and paste the output into `API_KEY`.
Keep `.env` private; it contains credentials. When you first run the bot, send it a message to get your Telegram
ID, add that numeric ID to `TELEGRAM_ALLOWED_USER_IDS`, then restart the service to apply the allowlist.

Example values (the token and key below are placeholders, not usable credentials):

```dotenv
TELEGRAM_BOT_TOKEN=123456789:PASTE_YOUR_SECRET_BOTFATHER_TOKEN
TELEGRAM_ALLOWED_USER_IDS=123456789
API_KEY=PASTE_OUTPUT_FROM_OPENSSL_RAND_HEX_32
```

4. Start the application:

```bash
docker compose up -d --build
docker compose logs -f app
```

- The bot automatically uses long polling.
- The API is published only on `127.0.0.1:3000` (not exposed to the internet).
- Access the API from your laptop through an SSH tunnel:

```bash
ssh -L 3000:127.0.0.1:3000 user@ip-vps
# Then open http://localhost:3000/healthz on your laptop
```

If you need a public API, change the port mapping in `docker-compose.yml` to `"3000:3000"` and restrict access with a firewall. Use a strong `API_KEY`.

### Webhook mode + HTTPS (domain)

1. Point your domain's A record (e.g. `scraper.example.com`) to your VPS IP.
2. Open ports **80** and **443** in your firewall.
3. Configure `.env`:

```dotenv
BOT_MODE=webhook
PUBLIC_URL=https://scraper.example.com
DOMAIN=scraper.example.com
TRUST_PROXY=true
```

4. Start the application:

```bash
docker compose --profile webhook up -d --build
docker compose logs -f app caddy
```

Caddy obtains a Let's Encrypt certificate automatically. The app log confirms that the Telegram webhook is active.

To expose **only** the webhook path (keeping the API local), replace the contents of `Caddyfile`:

```caddyfile
{$DOMAIN} {
	handle /telegram/webhook {
		reverse_proxy app:3000
	}
	respond 404
}
```

SQLite data is stored in the named volume `scraper_data`. Back it up with:

```bash
docker run --rm -v telegram-scraper_scraper_data:/data \
  -v "$PWD:/backup" alpine tar czf /backup/scraper-data.tgz -C /data .
```

(Adjust the volume name based on the output of `docker volume ls`.)

---

## 7. Environment variables

| Variable | Default | Description |
| --- | --- | --- |
| `TELEGRAM_BOT_TOKEN` | – | Token from BotFather. Empty = bot is disabled; the API still runs. |
| `TELEGRAM_ALLOWED_USER_IDS` | – | Comma-separated Telegram ID allowlist. Empty = all users are denied. |
| `API_KEY` | – | API key, at least 16 characters. Empty = `/api` returns 503. |
| `BOT_MODE` | `auto` | `polling`, `webhook`, or `auto` (webhook when `PUBLIC_URL` is set). |
| `PUBLIC_URL` | – | Required for webhook mode; must use `https://...`. |
| `WEBHOOK_PATH` | `/telegram/webhook` | Webhook path. |
| `WEBHOOK_SECRET` | Random on startup | Validated against Telegram's request header. |
| `PORT` / `HOST` | `3000` / `0.0.0.0` | Express bind address. |
| `DATA_DIR` | `./data` | SQLite data directory. |
| `CONFIG_DIR` | `./config/sources` | YAML source directory. |
| `LOG_LEVEL` | `info` | Pino log level. |
| `TIMEZONE` | `Asia/Jakarta` | Time zone used in bot display. |
| `TRUST_PROXY` | `false` | Set to `true` when behind Caddy/Nginx. |
| `DEFAULT_USER_AGENT` | `TelegramScraperBot/1.0 ...` | Default user agent. |
| `RESPECT_ROBOTS` | `true` | Respect `robots.txt`. |
| `ALLOW_ADHOC` | `true` | Allow `POST /api/scrape/adhoc`. |
| `JOB_CONCURRENCY` | `2` | Concurrent jobs. |
| `JOB_TIMEOUT_MS` | `120000` | Per-job timeout. |
| `MAX_QUEUE` | `50` | Maximum job queue size. |
| `MAX_RESULT_BYTES` | `10485760` | Maximum size of stored results. |
| `MAX_ITEMS` | `500` | Global maximum items per job. |
| `SECURITY_ENABLED` | `true` | Enable the security scanner. |
| `SECURITY_ALLOWED_DOMAINS` | – | **Required for scans**: comma-separated domains that may be tested. `example.com` includes subdomains; `*.example.com` matches subdomains only. |
| `SECURITY_RATE_LIMIT` | `20` | Requests per second for httpx, nuclei, katana, and dalfox. |
| `SECURITY_MAX_ACTIVE_SCANS` | `1` | Maximum concurrent scans. |
| `SECURITY_MAX_QUEUE` | `10` | Maximum scan queue size. |
| `SECURITY_COOLDOWN_SECONDS` | `60` | Minimum delay before the next scan of the same host. |
| `SECURITY_SCAN_TIMEOUT_MS` | `900000` | Maximum duration of one scan (15 minutes). |
| `SECURITY_MAX_FINDINGS` | `200` | Maximum findings per scan. |
| `SECURITY_MAX_PARAM_URLS` | `50` | Maximum parameterized URLs to test. |
| `SECURITY_DALFOX_MAX_URLS` | `10` | Maximum URLs for dalfox. |
| `SECURITY_SQLMAP_MAX_URLS` | `5` | Maximum URLs for sqlmap. |
| `SECURITY_NUCLEI_SEVERITY` | `critical,high,medium,low,info` | Nuclei template severity levels. |
| `SECURITY_NUCLEI_EXCLUDE_TAGS` | `dos,fuzz,intrusive,brute-force,credential-stuffing` | Nuclei tags to exclude. |
| `SECURITY_NUCLEI_TEMPLATES` | Auto-detected | Nuclei template path (Docker: `/opt/nuclei-templates`). |
| `SECURITY_*_BIN` | Tool name | Override binary paths: nuclei, httpx, katana, subfinder, dalfox, sqlmap, paramspider. |
| `SECURITY_REPORT_SEND` | `false` | Enable report email delivery. Requires `SMTP_HOST` and `SMTP_FROM`. |
| `SECURITY_REPORT_TO` | – | Default report recipient. |
| `SMTP_HOST` / `SMTP_PORT` | – / `587` | SMTP server and port. |
| `SMTP_SECURE` | `false` | Set to `true` for implicit TLS (usually port 465). |
| `SMTP_USER` / `SMTP_PASS` | – | SMTP credentials, if required. |
| `SMTP_FROM` | – | Report sender address. |

---

## 8. Security

- **API key** is required for `/api/*`; comparisons use constant time; rate limit is 120 requests/minute per IP; the job queue is capped (`MAX_QUEUE`).
- **Bot allowlist** — other users only receive their ID and cannot run commands.
- **Security scope** — scans only run against `SECURITY_ALLOWED_DOMAINS`; redirects to out-of-scope hosts are not followed. An empty scope rejects all scans.
- **Authorization confirmation** — the bot displays a confirmation button, and the API requires `confirmAuthorization: true`. No scan runs without an authorization statement.
- **Rate limits and cooldowns** — tool requests are capped by `SECURITY_RATE_LIMIT`, scans of the same host are separated by `SECURITY_COOLDOWN_SECONDS`, and the queue is bounded.
- **Safe templates** — nuclei excludes `dos`, `fuzz`, `intrusive`, and `brute-force` tags; interactsh is disabled. sqlmap uses detection-only mode (`--level=1 --risk=1`), without data dumps or an OS shell.
- **Redacted reports** — cookie values, session tokens, credentials, and Telegram IDs are omitted from reports that can be sent to a target.
- **No automatic email** — `SECURITY_REPORT_SEND=false` by default; sending always requires human confirmation.
- **Webhook** requests are verified using Telegram's secret token.
- **SSRF guard** on the ad hoc endpoint: only `http/https` is allowed; internal hostnames (`localhost`, `.local`, `.internal`, cloud metadata) are blocked; every resolved IP must be public; and redirects are revalidated. DNS lookups are also pinned at connection time using a dedicated agent to reduce DNS rebinding risk.
- **`robots.txt`** is respected by default; the per-origin delay is configured with `delayMs`.
- **CSV formula injection** is sanitized; bot input is escaped before it is sent as HTML.
- Raw data is never sent to third parties; all processing happens locally on your server.

YAML source files are treated as **trusted admin configuration** — do not grant untrusted users write access to the `config/` directory.

**Ethics and legal use:** follow the target website's Terms of Service and `robots.txt`, do not collect personal data without a legal basis, and do not overload target servers. You are responsible for how you use this tool.

---

## 9. Limitations

- Only **HTML over GET** is fetched. Sites requiring JavaScript rendering, interactive login, CAPTCHA, or a JSON API need additional support (e.g. Playwright).
- The queue and SQLite are **single-instance**. For multiple instances, move the queue to Redis/BullMQ and the database to Postgres.
- There is no scheduler/cron yet; jobs are started manually through the bot/API.
- CSV output is flat: array/object values are stored as JSON strings.

---

## 10. Troubleshooting

| Symptom | Cause / solution |
| --- | --- |
| Bot is unresponsive | Check `TELEGRAM_BOT_TOKEN` and `docker compose logs app`. Ensure your ID is on the allowlist. |
| `409 Conflict: terminated by other getUpdates` | Another bot instance may be running, or a webhook is still active. Set `BOT_MODE=polling` (this removes the webhook automatically) and restart. |
| API 503 | `API_KEY` has not been set. |
| API 401 | The `x-api-key` header is missing or incorrect. |
| Source config is missing | Check the `errors` field in `/api/sources` or the startup logs. |
| Empty results | The selector may be wrong, the site may render JavaScript, or `robots.txt` may block access. Try fetching the page with `curl` first. |
| HTTP 403 / Cloudflare | The site is blocking the bot. Follow its Terms of Service; do not try to bypass protections. |
| `SSRF blocked` | The ad hoc URL resolves to a private IP or localhost. This is intentionally blocked. |
| `EADDRINUSE` | Port 3000 is in use by another process; change `PORT`. |
| Docker build fails on better-sqlite3 | Run `docker compose build --no-cache` (internet access is required for the prebuild). |

---

## 11. Project structure

```
telegram-scraper/
├── src/
│   ├── index.js            # entry point, graceful shutdown
│   ├── config.js           # environment validation
│   ├── db.js               # SQLite (jobs/results)
│   ├── jobs.js             # queue, timeout, retry-free runner
│   ├── api.js              # REST API + auth + rate limiting
│   ├── bot.js              # Telegraf commands/actions/notifications
│   ├── sources.js          # YAML loader + validation
│   ├── scrape/
│   │   ├── engine.js       # pagination, detail, dedupe
│   │   ├── fetch.js        # robots, politeness, redirects, body limits
│   │   ├── extract.js      # field extraction
│   │   └── transforms.js   # value transforms
│   └── util/               # csv, ssrf, id
├── config/sources/*.yaml   # source definitions
├── docs/openapi.yaml
├── test/                   # unit + integration test
├── scripts/smoke.js
├── Dockerfile
├── docker-compose.yml
└── Caddyfile
```

## 12. Development

```bash
npm run dev          # watch mode
npm test             # Run the test suite
npm run smoke        # Scrape 5 items from books-demo
npm run smoke quotes-demo
```

### Contributing

Contributions that add features or fix bugs are welcome. To propose a change:

1. Open an issue describing the bug or feature and its expected behavior. For bug reports, include
   reproduction steps, expected and actual results, and relevant logs with secrets removed.
2. Fork the repository and create a focused branch for your change.
3. Make the smallest change that addresses the issue. Add or update tests for behavior changes, and update
   this README when user-facing behavior or configuration changes.
4. Run `npm test` and review your changes for accidental secrets or unrelated edits.
5. Open a pull request describing the problem, solution, and test results. Link the related issue when available.

For small typo or documentation fixes, you can open a pull request directly. Please do not include credentials,
private target data, or unrelated formatting changes.
