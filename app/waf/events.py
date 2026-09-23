"""Zdarzenie audytowe zgodne ze schematem z spec §8, FR-9."""
from __future__ import annotations

import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from .decision import DecisionResult
from .request import WafRequest

REDACTED_HEADERS = {"authorization", "cookie"}


@dataclass(frozen=True)
class Event:
    event_id: str
    timestamp: str
    method: str
    path: str
    client_ip: str
    headers_redacted: dict[str, str]
    body_size: int
    decision: str
    decision_reason: str
    rules_matched: list[str]
    ai_score: float
    ai_top_features: list[str]
    model_version: str
    latency_ms: float

    def as_dict(self) -> dict:
        return asdict(self)


def build_event(request: WafRequest, result: DecisionResult, latency_ms: float) -> Event:
    headers_redacted = {
        k: ("<redacted>" if k.lower() in REDACTED_HEADERS else v)
        for k, v in request.headers.items()
    }
    return Event(
        event_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc).isoformat(),
        method=request.method,
        path=request.path,
        client_ip=request.client_ip,
        headers_redacted=headers_redacted,
        body_size=len(request.body.encode("utf-8")),
        decision=result.decision.value,
        decision_reason=result.reason,
        rules_matched=result.rules_matched,
        ai_score=result.ai_score,
        ai_top_features=result.ai_top_features,
        model_version=result.model_version,
        latency_ms=round(latency_ms, 3),
    )
