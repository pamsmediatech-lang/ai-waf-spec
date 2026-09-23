"""Data plane: standalone reverse proxy (spec §5.3 wariant 4 - najprostsze wdrożenie).

Inline: każde żądanie przechodzi przez pipeline (rules+AI+decision) przed
dotarciem do backendu. `allow`/`monitor` -> przekazane dalej; `block`/
`challenge` -> odrzucone (spec §6.2, ponytail note w decision.py).
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request, Response

from .decision import Decision, Policy
from .pipeline import inspect
from .request import WafRequest
from .session_store import SessionStore

logger = logging.getLogger("ai_waf")

BLOCKED_DECISIONS = {Decision.BLOCK, Decision.CHALLENGE}
DEFAULT_MAX_BODY_BYTES = 1_000_000  # Warstwa 0 (spec §6.1 pkt 1): limit rozmiaru żądania

# RFC 7230 §6.1 -- nagłówki specyficzne dla pojedynczego hopa, nie dla
# treści; nie wolno ich bezmyślnie przepisywać między klientem a
# backendem, bo psują keep-alive/chunking po obu stronach.
HOP_BY_HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade", "host", "content-length",
}


def _strip_hop_by_hop(headers: dict[str, str] | httpx.Headers) -> dict[str, str]:
    return {k: v for k, v in headers.items() if k.lower() not in HOP_BY_HOP_HEADERS}


def create_app(
    backend_url: str,
    http_client: httpx.AsyncClient | None = None,
    policy: Policy | None = None,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        yield
        await app.state.http_client.aclose()

    app = FastAPI(title="AI-WAF", lifespan=lifespan)
    app.state.session_store = SessionStore()
    app.state.policy = policy or Policy()
    app.state.backend_url = backend_url.rstrip("/")
    app.state.http_client = http_client or httpx.AsyncClient()
    app.state.events: list[dict] = []  # ponytail: bufor w pamięci; upgrade do async pipeline -> SIEM (spec §5.1) w produkcji

    @app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
    async def catch_all(full_path: str, request: Request) -> Response:
        content_length = request.headers.get("content-length")
        if content_length is not None and content_length.isdigit() and int(content_length) > max_body_bytes:
            return _reject(413, "request_body_too_large")

        body_bytes = await request.body()
        if len(body_bytes) > max_body_bytes:
            return _reject(413, "request_body_too_large")

        waf_request = WafRequest(
            method=request.method,
            path="/" + full_path,
            client_ip=request.client.host if request.client else "unknown",
            headers=dict(request.headers),
            query={k: request.query_params.getlist(k) for k in request.query_params},
            body=body_bytes.decode("utf-8", errors="replace"),
        )

        result, event = inspect(waf_request, app.state.session_store, app.state.policy)
        app.state.events.append(event.as_dict())
        logger.info("ai_waf_event", extra={"event": event.as_dict()})

        if result.decision in BLOCKED_DECISIONS:
            return _reject(403, result.reason, decision=result.decision.value, event_id=event.event_id)

        try:
            upstream = await app.state.http_client.request(
                request.method,
                f"{app.state.backend_url}/{full_path}",
                headers=_strip_hop_by_hop(dict(request.headers)),
                params=request.query_params.multi_items(),
                content=body_bytes,
            )
        except httpx.RequestError:
            logger.exception("ai_waf_upstream_unreachable", extra={"event_id": event.event_id})
            return _reject(502, "upstream_unreachable", decision=result.decision.value, event_id=event.event_id)

        response_headers = _strip_hop_by_hop(upstream.headers)
        response_headers["X-AI-WAF-Decision"] = result.decision.value
        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            headers=response_headers,
            media_type=upstream.headers.get("content-type"),
        )

    def _reject(status_code: int, reason: str, decision: str = "block", event_id: str = "") -> Response:
        return Response(
            content=f'{{"error":"blocked","reason":"{reason}","event_id":"{event_id}"}}',
            status_code=status_code,
            media_type="application/json",
            headers={"X-AI-WAF-Decision": decision},
        )

    return app
