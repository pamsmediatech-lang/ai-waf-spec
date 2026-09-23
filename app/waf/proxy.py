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


def create_app(backend_url: str, http_client: httpx.AsyncClient | None = None, policy: Policy | None = None) -> FastAPI:
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

    @app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
    async def catch_all(full_path: str, request: Request) -> Response:
        body_bytes = await request.body()
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
            return Response(
                content=f'{{"error":"blocked","reason":"{result.reason}","event_id":"{event.event_id}"}}',
                status_code=403,
                media_type="application/json",
                headers={"X-AI-WAF-Decision": result.decision.value},
            )

        upstream = await app.state.http_client.request(
            request.method,
            f"{app.state.backend_url}/{full_path}",
            headers={k: v for k, v in request.headers.items() if k.lower() != "host"},
            params=dict(request.query_params),
            content=body_bytes,
        )
        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            headers={"X-AI-WAF-Decision": result.decision.value},
            media_type=upstream.headers.get("content-type"),
        )

    return app
