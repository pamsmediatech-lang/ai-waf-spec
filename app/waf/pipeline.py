"""Łączy warstwy 0-4 (normalize -> rules -> features -> scoring -> decision)
w jeden przebieg dla pojedynczego żądania, plus zdarzenie audytowe (§8)."""
from __future__ import annotations

import time

from . import features as features_mod
from . import rules as rules_mod
from . import scoring as scoring_mod
from .decision import DecisionResult, Policy, decide
from .events import Event, build_event
from .request import WafRequest
from .session_store import SessionStore

_DEFAULT_POLICY = Policy()


def inspect(request: WafRequest, store: SessionStore, policy: Policy = _DEFAULT_POLICY) -> tuple[DecisionResult, Event]:
    start = time.perf_counter()

    rule_matches = rules_mod.evaluate(request)
    client_state = store.record(request.client_ip, request.path)
    feats = features_mod.extract(request, rule_matches, client_state)
    ai_result = scoring_mod.score(feats)
    result = decide(rule_matches, ai_result, policy)

    latency_ms = (time.perf_counter() - start) * 1000
    event = build_event(request, result, latency_ms)
    return result, event
