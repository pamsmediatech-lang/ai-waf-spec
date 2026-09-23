"""Warstwa 2 (spec §6.1 pkt 3, §7.2): ekstrakcja cech dla AI Scoring Engine."""
from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass

from .request import WafRequest
from .rules import RuleMatch
from .session_store import ClientState


@dataclass(frozen=True)
class Features:
    max_field_entropy: float
    max_field_length: int
    rule_hit_count: int
    max_rule_severity: int
    requests_last_window: int
    unique_endpoints_last_window: int
    reputation_score: float


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def extract(request: WafRequest, rule_matches: list[RuleMatch], client_state: ClientState) -> Features:
    field_values = [v for _, v in request.fields()]
    entropies = [_shannon_entropy(v) for v in field_values] or [0.0]
    lengths = [len(v) for v in field_values] or [0]
    severities = [m.severity for m in rule_matches] or [0]

    return Features(
        max_field_entropy=max(entropies),
        max_field_length=max(lengths),
        rule_hit_count=len(rule_matches),
        max_rule_severity=max(severities),
        requests_last_window=len(client_state.request_times),
        unique_endpoints_last_window=len(client_state.endpoints),
        reputation_score=client_state.reputation_score,
    )
