# Authorized URL Resolver API

A small, production-oriented FastAPI service that accepts a short URL, follows **normal HTTP redirects**, and returns the final destination as clean JSON. It is designed for URLs and APIs that you own or are explicitly authorized to test.

> This project does not bypass CAPTCHA, anti-bot systems, timers, advertisements, authentication, rate limits, or any other access-control mechanism. It only uses ordinary HTTP requests and redirects.

## Features

- `POST /api/v1/resolve` with `{ "url": "https://..." }`
- `GET /bypass?link=YOUR_SHORT_LINK` returning the resolved destination in `resolved_url`
- `POST /api/v1/resolve/html` for normal HTTP redirects plus explicit HTML meta-refresh/JavaScript-location patterns
- `POST /api/v1/resolve/generic` accepting `{ "url": "...", "api_key": "..." }`
- `POST /api/v1/resolve/earnlinks` for authorized `earnlinks.in` URLs using a provider-specific BeautifulSoup adapter
- `GET /api/v1/resolve?url=...`
- Telegram-bot-ready `GET /api/v1/telegram/resolve?url=...`
- Follows 301/302/303/307/308 redirects with a configurable limit
- Optional HTML fallback is bounded by `MAX_HTML_REDIRECTS` and `MAX_HTML_BYTES`
- Returns the complete final URL, including query strings and fragments when supplied by the server
- Correctly treats URL text containing `error`, `failed`, or `timeout` as valid URL data; error classification is based on validation and actual HTTP client exceptions only
- Explicit JSON error envelopes with stable error codes
- Timeout, DNS, redirect-limit, malformed URL, and upstream-failure handling
- Explicit `upstream_blocked` errors for upstream 401/403/429 responses, including the blocked URL and status code
- Optional API key, exact host allowlist, and private-network blocking
- Structured request logging without logging response bodies
- Minimal public status page at `/` showing only `Online`
- OpenAPI docs at `/docs`
- Docker and Docker Compose support

## API contract

Success (`2xx`):

```json
{
  "ok": true,
  "requested_url": "https://short.example/error001",
  "final_url": "https://destination.example/path?slug=error001",
  "status_code": 200,
  "redirect_count": 1,
  "elapsed_ms": 143
}
```

Error (`4xx` or `5xx`):

```json
{
  "ok": false,
  "error": {
    "code": "upstream_timeout",
    "message": "the target did not respond before the configured timeout",
    "request_id": "abc123"
  }
}
```

A final HTTP `404` or `500` response is still a successful *resolution* because the redirect chain completed; its status is returned in `status_code`. Transport failures such as timeouts are API errors.

If a destination returns `401`, `403`, or `429` (for example, an access-control, Cloudflare, anti-bot, or rate-limit page), the resolver returns HTTP `502` with `error.code = "upstream_blocked"`, the upstream status, and the URL where the block occurred. It does not spoof cookies/referers, solve challenges, skip timers or advertisements, or attempt to bypass the protection. Use an authorized API/integration or allowlisted service contract when access is required.

## Simple GET redirector

```bash
curl -sG http://127.0.0.1:8000/bypass \
  --data-urlencode 'link=https://your-authorized-shortener.example/abc' | jq
```

Success responses contain `resolved_url`:

```json
{
  "ok": true,
  "requested_url": "https://short.example/abc",
  "resolved_url": "https://destination.example/path",
  "status_code": 200,
  "redirect_count": 1,
  "elapsed_ms": 143
}
```

The route follows ordinary HTTP `Location` redirects only and is intentionally usable without an API key. The root page is a status page only; use `/bypass?link=...` or the documented API routes for resolution. It does not use a third-party API or attempt to bypass access controls. The protected JSON API routes can still use `API_KEY` through `X-API-Key`.

## HTML redirect fallback

Use `/api/v1/resolve/html` only when an authorized service returns an HTML redirect page instead of an HTTP `Location` header. The parser handles explicit `<meta http-equiv="refresh" content="0; url=/next">` and simple `window.location.href = "..."` / `location.replace("...")` patterns. It does **not** execute JavaScript, scrape arbitrary anchor tags, defeat timers, or bypass CAPTCHA, anti-bot pages, advertisements, authentication, or other access controls. Relative targets are resolved against the response URL and pass the same URL validation/private-network protections as the initial request.

Example:

```bash
curl -s http://127.0.0.1:8000/api/v1/resolve/html \
  -H 'content-type: application/json' \
  -d '{"url":"https://your-authorized-shortener.example/abc"}' | jq
```

The parser boilerplate is reusable in `extract_html_redirect(html, base_url)`. It returns a target URL or `None`; callers should treat `None` as “no supported HTML redirect found”, not as an API failure.

## Generic body-based resolver route

Set `API_KEY` in the environment and send it in the request body:

```bash
curl -s http://127.0.0.1:8000/api/v1/resolve/generic \
  -H 'content-type: application/json' \
  -d '{"url":"https://your-authorized-shortener.example/abc","api_key":"YOUR_API_KEY"}' | jq
```

This route uses `httpx.AsyncClient` for ordinary HTTP redirects and BeautifulSoup via `app/providers/generic.py` for explicit `<meta http-equiv="refresh" content="0; url=...">` targets. It does not execute scripts, scrape arbitrary links, or bypass timers, ads, CAPTCHA, anti-bot controls, authentication, or other protected workflows. If `API_KEY` is unset, the body-key route is disabled with a configuration error rather than accepting an empty secret.

## earnlinks.in provider adapter

The provider endpoint accepts only `earnlinks.in` and `www.earnlinks.in` hostnames:

```bash
curl -s http://127.0.0.1:8000/api/v1/resolve/earnlinks \
  -H 'content-type: application/json' \
  -d '{"url":"https://earnlinks.in/your-authorized-short-url"}' | jq
```

`app/providers/earnlinks.py` contains the reusable `is_earnlinks_url()` and `extract_earnlinks_html_redirect()` functions. The adapter uses BeautifulSoup only for an explicit `<meta http-equiv="refresh">` target and ignores arbitrary links, scripts, forms, countdowns, advertisements, CAPTCHA, anti-bot checks, authentication, and other access-control mechanisms. It is intended for URLs you own or are authorized to test; if the service requires a user action or protected-page bypass, the endpoint returns the page result rather than attempting to defeat it.

## Run locally

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000 or use:

```bash
curl -s http://127.0.0.1:8000/api/v1/resolve \
  -H 'content-type: application/json' \
  -d '{"url":"https://httpbin.org/redirect/2"}' | jq
```

## Telegram bot integration

No Telegram token is stored or required by this API. Your bot can call:

```text
GET https://YOUR_HOST/api/v1/telegram/resolve?url=https%3A%2F%2Fshort.example%2Fabc
```

If `API_KEY` is configured, send `X-API-Key: YOUR_SECRET`. The bot should inspect the JSON `ok` field and reply with `final_url` on success or `error.message` on failure. Never infer failure by searching for words in `final_url`.

## Configuration

See `.env.example`. For a public service, keep `BLOCK_PRIVATE_NETWORKS=true` and preferably set `ALLOWED_HOSTS` to the domains you control. This reduces SSRF risk, but an allowlist and network egress policy are still recommended for production.

## Docker deployment

```bash
cp .env.example .env
# edit .env; set API_KEY and ALLOWED_HOSTS where appropriate
docker compose up -d --build
curl http://localhost:8000/healthz
```

For a VPS, put Nginx or Caddy in front of port 8000, terminate TLS there, set a firewall rule to expose only 80/443, and keep the application bound to the internal network. Example systemd command:

```ini
[Service]
WorkingDirectory=/opt/url-resolver-api
EnvironmentFile=/opt/url-resolver-api/.env
ExecStart=/opt/url-resolver-api/.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers 2
Restart=always
```

The same container can be deployed to any host that supports Docker containers, including a managed container service. Set environment variables through the platform secret/configuration UI rather than committing `.env`.

## GitHub

```bash
git init
git add .
git commit -m "Initial authorized URL resolver API"
git branch -M main
git remote add origin https://github.com/YOUR_USER/url-resolver-api.git
git push -u origin main
```

Do not commit `.env`, API keys, bot tokens, or private URLs.

## Testing

```bash
pytest -q
```

The tests use a local test server and explicitly cover a successful URL containing the words `error`, `failed`, and `timeout`, plus redirects, validation, and actual timeout behavior.
