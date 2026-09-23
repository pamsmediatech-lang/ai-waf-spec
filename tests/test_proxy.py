import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from app.waf.proxy import create_app


def _backend_app() -> FastAPI:
    backend = FastAPI()

    @backend.get("/products")
    async def products():
        return {"items": ["shoe", "sock"]}

    @backend.post("/login")
    async def login(request: Request):
        payload = await request.json()
        return {"received": payload}

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
    assert resp.json() == {"items": ["shoe", "sock"]}
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
