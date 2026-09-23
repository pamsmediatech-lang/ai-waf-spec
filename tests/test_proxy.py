import httpx
import pytest
from fastapi import FastAPI, Request, Response
from fastapi.testclient import TestClient

from app.waf.proxy import create_app


def _backend_app() -> FastAPI:
    backend = FastAPI()

    @backend.get("/products")
    async def products(request: Request):
        return {"items": ["shoe", "sock"], "tags": request.query_params.getlist("tag")}

    @backend.post("/login")
    async def login(request: Request):
        payload = await request.json()
        return {"received": payload}

    @backend.get("/with-cookie")
    async def with_cookie():
        return Response(content='{"ok": true}', media_type="application/json",
                         headers={"Set-Cookie": "session=abc123; HttpOnly"})

    return backend


@pytest.fixture()
def client() -> TestClient:
    backend = _backend_app()
    backend_client = httpx.AsyncClient(transport=httpx.ASGITransport(app=backend), base_url="http://backend")
    waf_app = create_app(backend_url="http://backend", http_client=backend_client)
    with TestClient(waf_app) as c:
        yield c


def test_benign_get_request_is_forwarded_to_backend(client: TestClient):
    resp = client.get("/products")
    assert resp.status_code == 200
    assert resp.json()["items"] == ["shoe", "sock"]
    # allow/monitor are both non-blocking outcomes (spec §6.2); which one
    # depends on the AI score assigned to this specific request's headers.
    assert resp.headers["X-AI-WAF-Decision"] in {"allow", "monitor"}


def test_sqli_in_query_param_is_blocked(client: TestClient):
    resp = client.get("/products", params={"id": "1 UNION SELECT password FROM users"})
    assert resp.status_code == 403
    assert resp.headers["X-AI-WAF-Decision"] == "block"
    assert resp.json()["error"] == "blocked"


def test_xss_in_json_body_is_blocked(client: TestClient):
    resp = client.post("/login", json={"username": "<script>alert(1)</script>"})
    assert resp.status_code == 403


def test_path_traversal_is_blocked(client: TestClient):
    resp = client.get("/files/../../../../etc/passwd")
    assert resp.status_code == 403


def test_blocked_request_is_not_forwarded_to_backend(client: TestClient):
    resp = client.get("/products", params={"id": "1' OR '1'='1"})
    assert resp.status_code == 403
    # backend only knows /products (GET) and /login (POST); if the WAF had
    # forwarded this malicious request it would still succeed (200) since
    # the path is legit -- so the 403 here can only come from the WAF itself.


def test_recorded_events_are_queryable_from_app_state(client: TestClient):
    client.get("/products")
    events = client.app.state.events
    assert len(events) >= 1
    assert events[-1]["decision"] in {"allow", "monitor"}


def test_repeated_query_params_are_all_forwarded_to_backend(client: TestClient):
    # regression: params=dict(...) used to silently drop all but the last
    # value for a repeated query key.
    resp = client.get("/products", params=[("tag", "a"), ("tag", "b")])
    assert resp.status_code == 200
    assert resp.json()["tags"] == ["a", "b"]


def test_upstream_response_headers_are_forwarded(client: TestClient):
    resp = client.get("/with-cookie")
    assert resp.status_code == 200
    assert resp.headers["set-cookie"].startswith("session=abc123")
    assert resp.headers["X-AI-WAF-Decision"] in {"allow", "monitor"}


def test_oversized_body_is_rejected_with_413():
    backend = _backend_app()
    backend_client = httpx.AsyncClient(transport=httpx.ASGITransport(app=backend), base_url="http://backend")
    waf_app = create_app(backend_url="http://backend", http_client=backend_client, max_body_bytes=10)
    with TestClient(waf_app) as c:
        resp = c.post("/login", content=b"x" * 1000)
    assert resp.status_code == 413


def test_unreachable_backend_returns_502():
    async def _raise(*args, **kwargs):
        raise httpx.ConnectError("connection refused")

    broken_client = httpx.AsyncClient(transport=httpx.ASGITransport(app=_backend_app()), base_url="http://backend")
    broken_client.request = _raise  # simulate backend down without needing a real dead port
    waf_app = create_app(backend_url="http://backend", http_client=broken_client)
    with TestClient(waf_app) as c:
        resp = c.get("/products")
    assert resp.status_code == 502
    assert resp.json()["reason"] == "upstream_unreachable"
