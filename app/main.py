"""Authorized URL redirect resolver API.

This service follows normal HTTP redirects only. It does not bypass CAPTCHA,
anti-bot systems, timers, ads, authentication, or other access controls.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import re
import socket
import time
from contextlib import asynccontextmanager
from html import unescape
from html.parser import HTMLParser
from typing import Any, Callable
from urllib.parse import urljoin, urlparse

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.providers.earnlinks import extract_earnlinks_html_redirect, is_earnlinks_url
from app.providers.generic import extract_standard_html_redirect

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
API_KEY = os.getenv("API_KEY", "").strip()
REQUEST_TIMEOUT_SECONDS = float(os.getenv("REQUEST_TIMEOUT_SECONDS", "10"))
MAX_REDIRECTS = int(os.getenv("MAX_REDIRECTS", "10"))
MAX_HTML_REDIRECTS = int(os.getenv("MAX_HTML_REDIRECTS", "3"))
MAX_HTML_BYTES = int(os.getenv("MAX_HTML_BYTES", "1048576"))
MAX_URL_LENGTH = int(os.getenv("MAX_URL_LENGTH", "4096"))
BLOCK_PRIVATE_NETWORKS = os.getenv("BLOCK_PRIVATE_NETWORKS", "true").lower() not in {"0", "false", "no"}
ALLOWED_HOSTS = {h.strip().lower() for h in os.getenv("ALLOWED_HOSTS", "").split(",") if h.strip()}
USER_AGENT = os.getenv("USER_AGENT", "authorized-url-resolver/1.0")

logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("url-resolver")


class ResolveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str = Field(..., min_length=1, max_length=MAX_URL_LENGTH)

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        value = value.strip()
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("url must be an absolute http(s) URL")
        if parsed.username or parsed.password:
            raise ValueError("URLs with embedded credentials are not accepted")
        return value


class GenericResolveRequest(ResolveRequest):
    api_key: str = Field(..., min_length=1, max_length=256)


class ResolveResponse(BaseModel):
    ok: bool = True
    requested_url: str
    final_url: str
    status_code: int
    redirect_count: int
    html_redirect_count: int = 0
    elapsed_ms: int


class BypassResponse(BaseModel):
    ok: bool = True
    requested_url: str
    resolved_url: str
    status_code: int
    redirect_count: int
    elapsed_ms: int


class ErrorResponse(BaseModel):
    ok: bool = False
    error: dict[str, Any]


class HTMLRedirectParser(HTMLParser):
    """Collect only explicit HTML meta-refresh targets; do not scrape arbitrary links."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.refresh_content: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "meta":
            return
        values = {key.lower(): (value or "") for key, value in attrs}
        if values.get("http-equiv", "").lower() == "refresh":
            self.refresh_content = values.get("content", "")


def extract_html_redirect(html: str, base_url: str) -> str | None:
    """Return an explicit meta-refresh or JS location target, if present.

    This is intentionally conservative: it does not execute JavaScript, scrape
    arbitrary anchors, or attempt to bypass an interstitial/access-control page.
    """
    parser = HTMLRedirectParser()
    parser.feed(html)
    if parser.refresh_content:
        match = re.match(r"^\s*\d+\s*;\s*url\s*=\s*[\"']?([^\"']+?)\s*[\"']?\s*$", parser.refresh_content, re.IGNORECASE)
        if match:
            return urljoin(base_url, unescape(match.group(1).strip()))
    match = re.search(r"(?:window\.location|location)\.(?:href|replace)\s*(?:=|\()\s*[\"']([^\"']+)[\"']", html, re.IGNORECASE)
    if match:
        return urljoin(base_url, unescape(match.group(1).strip()))
    return None


@asynccontextmanager
async def lifespan(app: FastAPI):
    limits = httpx.Limits(max_connections=100, max_keepalive_connections=20)
    timeout = httpx.Timeout(REQUEST_TIMEOUT_SECONDS, connect=REQUEST_TIMEOUT_SECONDS)
    app.state.http_client = httpx.AsyncClient(
        follow_redirects=True,
        max_redirects=MAX_REDIRECTS,
        timeout=timeout,
        limits=limits,
        headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
    )
    logger.info("resolver_started max_redirects=%s timeout_seconds=%s", MAX_REDIRECTS, REQUEST_TIMEOUT_SECONDS)
    try:
        yield
    finally:
        await app.state.http_client.aclose()
        logger.info("resolver_stopped")


app = FastAPI(
    title="Authorized URL Resolver API",
    version="1.0.0",
    description="Resolve an authorized short URL using normal HTTP redirects.",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    detail = exc.detail
    if isinstance(detail, dict) and detail.get("ok") is False:
        body = detail
    else:
        request_id = request.headers.get("x-request-id", "")[:128] or os.urandom(8).hex()
        code = "unauthorized" if exc.status_code == 401 else "request_rejected"
        body = error_payload(code, str(detail), request_id).model_dump()
    return JSONResponse(status_code=exc.status_code, content=body, headers=exc.headers or {})


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    request_id = request.headers.get("x-request-id", "")[:128] or os.urandom(8).hex()
    return JSONResponse(status_code=422, content=error_payload("validation_error", "request validation failed", request_id).model_dump())


def api_key_guard(x_api_key: str | None = Header(default=None)) -> None:
    if API_KEY and x_api_key != API_KEY:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid API key")


def validate_body_api_key(api_key: str) -> None:
    if not API_KEY:
        raise HTTPException(status_code=503, detail="body API key authentication is not configured")
    if api_key != API_KEY:
        raise HTTPException(status_code=401, detail="invalid API key")


def _is_private_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.is_private or address.is_loopback or address.is_link_local or address.is_reserved or address.is_multicast or address.is_unspecified


def validate_target_host(url: str) -> None:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        raise HTTPException(status_code=422, detail="url must contain a hostname")
    if ALLOWED_HOSTS and host not in ALLOWED_HOSTS:
        raise HTTPException(status_code=403, detail="target host is not allowed")
    if not BLOCK_PRIVATE_NETWORKS:
        return
    try:
        addresses = {info[4][0] for info in socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)}
    except socket.gaierror as exc:
        raise HTTPException(status_code=502, detail="target hostname could not be resolved") from exc
    if any(_is_private_ip(address) for address in addresses):
        raise HTTPException(status_code=403, detail="private or local network targets are blocked")


def error_payload(code: str, message: str, request_id: str) -> ErrorResponse:
    return ErrorResponse(error={"code": code, "message": message, "request_id": request_id})


async def resolve_url(request: Request, payload: ResolveRequest, _: None = Depends(api_key_guard), allow_html_redirects: bool = False, html_redirect_extractor: Callable[[str, str], str | None] = extract_html_redirect) -> ResolveResponse:
    request_id = request.headers.get("x-request-id", "")[:128] or os.urandom(8).hex()
    started = time.perf_counter()
    logger.info("resolve_started request_id=%s url=%s", request_id, payload.url)
    validate_target_host(payload.url)
    try:
        client = getattr(request.app.state, "http_client", None)
        owns_client = client is None
        if owns_client:
            timeout = httpx.Timeout(REQUEST_TIMEOUT_SECONDS, connect=REQUEST_TIMEOUT_SECONDS)
            client = httpx.AsyncClient(follow_redirects=True, max_redirects=MAX_REDIRECTS, timeout=timeout, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
        current_url = payload.url
        html_redirect_count = 0
        try:
            while True:
                validate_target_host(current_url)
                response = await client.get(current_url)
                content_type = response.headers.get("content-type", "").lower()
                if not allow_html_redirects or "text/html" not in content_type or html_redirect_count >= MAX_HTML_REDIRECTS:
                    break
                html = response.content[:MAX_HTML_BYTES].decode(response.encoding or "utf-8", errors="replace")
                target = html_redirect_extractor(html, str(response.url))
                if not target or target == str(response.url):
                    break
                current_url = ResolveRequest(url=target).url
                html_redirect_count += 1
        finally:
            if owns_client:
                await client.aclose()
    except httpx.TimeoutException as exc:
        logger.warning("resolve_timeout request_id=%s url=%s", request_id, payload.url)
        raise HTTPException(status_code=504, detail=error_payload("upstream_timeout", "the target did not respond before the configured timeout", request_id).model_dump()) from exc
    except httpx.TooManyRedirects as exc:
        logger.warning("resolve_redirect_limit request_id=%s url=%s", request_id, payload.url)
        raise HTTPException(status_code=508, detail=error_payload("redirect_limit_exceeded", "the target exceeded the maximum redirect count", request_id).model_dump()) from exc
    except httpx.InvalidURL as exc:
        raise HTTPException(status_code=422, detail=error_payload("invalid_url", "the target URL is invalid", request_id).model_dump()) from exc
    except httpx.RequestError as exc:
        logger.warning("resolve_upstream_error request_id=%s type=%s", request_id, type(exc).__name__)
        raise HTTPException(status_code=502, detail=error_payload("upstream_request_failed", "the target could not be reached", request_id).model_dump()) from exc

    elapsed_ms = round((time.perf_counter() - started) * 1000)
    redirect_count = len(response.history)
    logger.info("resolve_succeeded request_id=%s status=%s redirects=%s elapsed_ms=%s", request_id, response.status_code, redirect_count, elapsed_ms)
    return ResolveResponse(
        requested_url=payload.url,
        final_url=str(response.url),
        status_code=response.status_code,
        redirect_count=redirect_count,
        html_redirect_count=html_redirect_count,
        elapsed_ms=elapsed_ms,
    )


@app.get("/healthz", response_model=dict[str, str])
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/bypass", response_model=BypassResponse)
async def bypass(request: Request, link: str = Query(..., min_length=1, max_length=MAX_URL_LENGTH)) -> BypassResponse:
    """Public JSON redirect client; no third-party API key is required."""
    try:
        payload = ResolveRequest(url=link)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    result = await resolve_url(request, payload)
    return BypassResponse(
        requested_url=result.requested_url,
        resolved_url=result.final_url,
        status_code=result.status_code,
        redirect_count=result.redirect_count,
        elapsed_ms=result.elapsed_ms,
    )


@app.post("/api/v1/resolve", response_model=ResolveResponse, responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}, 422: {"model": ErrorResponse}, 502: {"model": ErrorResponse}, 504: {"model": ErrorResponse}, 508: {"model": ErrorResponse}})
async def resolve_post(request: Request, payload: ResolveRequest, _: None = Depends(api_key_guard)) -> ResolveResponse:
    return await resolve_url(request, payload, _)


@app.post("/api/v1/resolve/html", response_model=ResolveResponse)
async def resolve_html_post(request: Request, payload: ResolveRequest, _: None = Depends(api_key_guard)) -> ResolveResponse:
    """Follow HTTP redirects plus explicit meta-refresh/JS-location patterns."""
    return await resolve_url(request, payload, _, allow_html_redirects=True)


@app.post("/api/v1/resolve/generic", response_model=ResolveResponse)
async def resolve_generic_post(request: Request, payload: GenericResolveRequest) -> ResolveResponse:
    """Generic body-based resolver: accepts url and configured api_key."""
    validate_body_api_key(payload.api_key)
    return await resolve_url(
        request,
        ResolveRequest(url=payload.url),
        allow_html_redirects=True,
        html_redirect_extractor=extract_standard_html_redirect,
    )


@app.post("/api/v1/resolve/earnlinks", response_model=ResolveResponse)
async def resolve_earnlinks_post(request: Request, payload: ResolveRequest, _: None = Depends(api_key_guard)) -> ResolveResponse:
    """Resolve authorized earnlinks.in URLs using HTTP redirects and meta-refresh only."""
    if not is_earnlinks_url(payload.url):
        raise HTTPException(status_code=422, detail="only earnlinks.in URLs are supported by this provider endpoint")
    return await resolve_url(request, payload, _, allow_html_redirects=True, html_redirect_extractor=extract_earnlinks_html_redirect)


@app.get("/api/v1/resolve", response_model=ResolveResponse)
async def resolve_get(request: Request, url: str = Query(..., min_length=1, max_length=MAX_URL_LENGTH), _: None = Depends(api_key_guard)) -> ResolveResponse:
    try:
        payload = ResolveRequest(url=url)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return await resolve_url(request, payload, _)


@app.get("/api/v1/telegram/resolve", response_model=ResolveResponse)
async def telegram_resolve(request: Request, url: str = Query(..., min_length=1, max_length=MAX_URL_LENGTH), _: None = Depends(api_key_guard)) -> ResolveResponse:
    """Telegram-bot-ready GET endpoint; pass the response JSON directly to the bot."""
    return await resolve_get(request, url, _)


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def web_ui() -> str:
    return INDEX_HTML


INDEX_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Authorized Link Shortcut</title><style>
:root{color-scheme:dark;font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(circle at 15% 0,#304a87 0,#111a35 40%,#070b16 100%);color:#f5f7ff;display:grid;place-items:center;padding:22px}.card{width:min(820px,100%);background:rgba(16,24,46,.94);border:1px solid #3e4e7d;border-radius:26px;padding:clamp(24px,5vw,48px);box-shadow:0 24px 90px #0009}.eyebrow{display:inline-flex;align-items:center;gap:8px;padding:7px 11px;border:1px solid #405183;border-radius:999px;background:#172548;color:#aebeff;font-size:12px;font-weight:800;letter-spacing:.08em;text-transform:uppercase}.dot{width:8px;height:8px;border-radius:50%;background:#55e0a5;box-shadow:0 0 12px #55e0a5}h1{margin:18px 0 10px;font-size:clamp(29px,5vw,48px);letter-spacing:-.04em;line-height:1.05}.intro{color:#bdc9e6;line-height:1.65;margin:0 0 28px;max-width:680px}.row{display:flex;gap:10px}@media(max-width:620px){.row{flex-direction:column}}input{width:100%;padding:15px 16px;border-radius:13px;border:1px solid #4a5c8c;background:#0a1227;color:#fff;font-size:16px;outline:none}input:focus{border-color:#91a0ff;box-shadow:0 0 0 3px #7180ff33}button{padding:15px 22px;border:0;border-radius:13px;background:linear-gradient(135deg,#8292ff,#5b6be9);color:#fff;font-weight:800;font-size:15px;cursor:pointer;white-space:nowrap}button:disabled{opacity:.6;cursor:wait}.label{font-size:11px;text-transform:uppercase;letter-spacing:.14em;color:#9eadd2;margin:26px 0 8px}.box{background:#090f20;border:1px solid #30416f;border-radius:14px;padding:15px 16px;overflow-wrap:anywhere;line-height:1.55;min-height:52px}.box a{color:#b8c3ff;text-decoration:none}.box a:hover{text-decoration:underline}.box.destination{border-color:#3da57d;background:#09201d}.destination a{color:#7ee2b6}.box.shortcut{border-color:#6d5dc6;background:#17152d}.shortcut a{color:#d1c5ff}.status{margin-top:16px;color:#b6c2df;font-size:14px}.status.success{color:#75e0b1}.note{font-size:13px;color:#8998bd;margin:24px 0 0;line-height:1.6}.empty{color:#7483a8}</style></head>
<body><main class="card"><div class="eyebrow"><span class="dot"></span> Shortcut online</div><h1>Authorized Link Shortcut</h1><p class="intro">Open this page with a link to follow its normal server redirects. Your original server link stays visible above, and the final resolved link appears below—no third-party API key is needed for this browser shortcut.</p>
<form id="form"><div class="row"><input id="url" type="url" placeholder="https://your-authorized-domain.example/abc" required><button id="submit" type="submit">Resolve link</button></div></form>
<div class="label">Original server link</div><div class="box" id="original"><span class="empty">Waiting for a link…</span></div>
<div class="label">Resolved / shortcut destination</div><div class="box destination" id="destination"><span class="empty">The final server URL will appear here.</span></div>
<div class="label">Shareable shortcut link</div><div class="box shortcut" id="shortcut"><span class="empty">Resolve a link to create its shortcut URL.</span></div>
<div class="status" id="status">Ready. This resolver only follows standard HTTP redirects.</div><p class="note">For links you own or are authorized to test. This service does not defeat CAPTCHA, anti-bot checks, timers, ads, authentication, rate limits, or other access controls.</p></main>
<script>const form=document.querySelector('#form'),input=document.querySelector('#url'),original=document.querySelector('#original'),destination=document.querySelector('#destination'),shortcut=document.querySelector('#shortcut'),status=document.querySelector('#status'),button=document.querySelector('#submit');function showLink(el,value,empty='—'){el.replaceChildren();if(value){const a=document.createElement('a');a.href=value;a.textContent=value;a.target='_blank';a.rel='noopener noreferrer';el.appendChild(a)}else{const span=document.createElement('span');span.className='empty';span.textContent=empty;el.appendChild(span)}}function showText(el,value,kind=''){el.textContent=value;if(kind)el.className='status '+kind}async function resolve(){const value=input.value.trim();if(!value)return;button.disabled=true;showLink(original,value);destination.textContent='Resolving…';shortcut.textContent='Preparing shortcut…';showText(status,'Following standard server redirects…');try{const r=await fetch('/bypass?link='+encodeURIComponent(value));const data=await r.json();if(data.ok){showLink(destination,data.resolved_url);const share=location.origin+'/?link='+encodeURIComponent(value);showLink(shortcut,share);showText(status,'Shortcut is online • resolved successfully • HTTP '+data.status_code+' • '+data.redirect_count+' redirect(s)','success')}else{destination.textContent='Could not resolve this URL';shortcut.textContent='No shortcut was created';showText(status,data.error?.message||'The resolver returned an error.')}}catch(err){destination.textContent='Could not resolve this URL';shortcut.textContent='No shortcut was created';showText(status,err.message||'The request failed.')}finally{button.disabled=false}}form.addEventListener('submit',e=>{e.preventDefault();resolve()});const prefill=new URLSearchParams(location.search).get('link');if(prefill){input.value=prefill;resolve()}</script></body></html>"""
