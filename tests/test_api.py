import asyncio

import httpx
import pytest
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread


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
async def test_invalid_scheme_is_api_error(app_client):
    transport = httpx.ASGITransport(app=app_client)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/v1/resolve", json={"url": "javascript:alert(1)"})
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_healthz(app_client):
    transport = httpx.ASGITransport(app=app_client)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/healthz")
    assert response.json() == {"status": "ok"}
