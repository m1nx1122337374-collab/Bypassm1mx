import asyncio

import httpx
import pytest
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

from app.providers.earnlinks import extract_earnlinks_html_redirect, is_earnlinks_url


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/short/error001":
            self.send_response(302)
            self.send_header("Location", "/destination?slug=error001&state=failed-timeout")
            self.end_headers()
        elif self.path.startswith("/destination"):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
        elif self.path == "/html/meta":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b'<meta http-equiv="refresh" content="0; url=/destination?via=meta">')
        elif self.path == "/html/js":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b'<script>window.location.href="/destination?via=js"</script>')
        elif self.path == "/slow":
            import time
            time.sleep(0.2)
            self.send_response(200)
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *_args):
        pass


@pytest.fixture(scope="module")
def target_server():
    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    thread.join(timeout=2)


@pytest.fixture
def app_client(monkeypatch):
    monkeypatch.setenv("BLOCK_PRIVATE_NETWORKS", "false")
    from app.main import app
    return app


@pytest.mark.asyncio
async def test_success_does_not_scan_url_for_error_words(app_client, target_server):
    transport = httpx.ASGITransport(app=app_client)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/v1/resolve", json={"url": f"{target_server}/short/error001"})
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["final_url"].endswith("/destination?slug=error001&state=failed-timeout")
    assert body["redirect_count"] == 1


@pytest.mark.asyncio
async def test_bypass_get_returns_resolved_url(app_client, target_server):
    transport = httpx.ASGITransport(app=app_client)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/bypass", params={"link": f"{target_server}/short/error001"})
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["resolved_url"].endswith("/destination?slug=error001&state=failed-timeout")
    assert "final_url" not in body


@pytest.mark.asyncio
async def test_bypass_get_rejects_invalid_link(app_client):
    transport = httpx.ASGITransport(app=app_client)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/bypass", params={"link": "javascript:alert(1)"})
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_invalid_scheme_is_api_error(app_client):
    transport = httpx.ASGITransport(app=app_client)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/v1/resolve", json={"url": "javascript:alert(1)"})
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_html_endpoint_follows_explicit_meta_refresh(app_client, target_server):
    transport = httpx.ASGITransport(app=app_client)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/v1/resolve/html", json={"url": f"{target_server}/html/meta"})
    assert response.status_code == 200
    body = response.json()
    assert body["final_url"].endswith("/destination?via=meta")
    assert body["html_redirect_count"] == 1


@pytest.mark.asyncio
async def test_html_parser_is_conservative(app_client, target_server):
    transport = httpx.ASGITransport(app=app_client)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/v1/resolve/html", json={"url": f"{target_server}/html/js"})
    assert response.status_code == 200
    assert response.json()["final_url"].endswith("/destination?via=js")


@pytest.mark.asyncio
async def test_generic_route_uses_body_api_key_and_beautifulsoup(app_client, target_server, monkeypatch):
    import app.main as main_module
    monkeypatch.setattr(main_module, "API_KEY", "test-secret")
    transport = httpx.ASGITransport(app=app_client)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/v1/resolve/generic",
            json={"url": f"{target_server}/html/meta", "api_key": "test-secret"},
        )
    assert response.status_code == 200
    assert response.json()["final_url"].endswith("/destination?via=meta")


@pytest.mark.asyncio
async def test_generic_route_rejects_wrong_body_api_key(app_client, monkeypatch):
    import app.main as main_module
    monkeypatch.setattr(main_module, "API_KEY", "test-secret")
    transport = httpx.ASGITransport(app=app_client)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/v1/resolve/generic",
            json={"url": "https://example.com/short", "api_key": "wrong"},
        )
    assert response.status_code == 401


def test_earnlinks_adapter_accepts_only_explicit_meta_refresh():
    html = '<a href="https://not-used.example">ignore</a><meta http-equiv="refresh" content="0; url=/next">'
    assert is_earnlinks_url("https://earnlinks.in/example")
    assert not is_earnlinks_url("https://example.com/earnlinks")
    assert extract_earnlinks_html_redirect(html, "https://earnlinks.in/example") == "https://earnlinks.in/next"
    assert extract_earnlinks_html_redirect('<script>location.href="/ignored"</script>', "https://earnlinks.in/example") is None


@pytest.mark.asyncio
async def test_earnlinks_endpoint_rejects_other_hosts(app_client):
    transport = httpx.ASGITransport(app=app_client)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/v1/resolve/earnlinks", json={"url": "https://example.com/short"})
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_healthz(app_client):
    transport = httpx.ASGITransport(app=app_client)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/healthz")
    assert response.json() == {"status": "ok"}
