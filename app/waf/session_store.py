"""Stan sesji/klienta w oknie czasowym (spec §5 "feature store online", §7.2).

ponytail: magazyn w pamięci procesu, wystarczający dla jednego węzła
inline i testów. Upgrade do zewnętrznego store (Redis) gdy data plane
będzie skalowany poziomo na wiele instancji dzielących stan.
"""
from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field

WINDOW_SECONDS = 60.0


@dataclass
class ClientState:
    request_times: list[float] = field(default_factory=list)
    endpoints: set[str] = field(default_factory=set)
    reputation_score: float = 0.0  # aktualizowane przez §6.3 (LLM feedback), 0..1


class SessionStore:
    def __init__(self, window_seconds: float = WINDOW_SECONDS) -> None:
        self._window = window_seconds
        self._clients: dict[str, ClientState] = defaultdict(ClientState)

    def record(self, client_ip: str, path: str, now: float | None = None) -> ClientState:
        now = time.time() if now is None else now
        state = self._clients[client_ip]
        state.request_times.append(now)
        state.request_times = [t for t in state.request_times if now - t <= self._window]
        state.endpoints.add(path)
        return state

    def get(self, client_ip: str) -> ClientState:
        return self._clients[client_ip]

    def bump_reputation(self, client_ip: str, delta: float) -> None:
        state = self._clients[client_ip]
        state.reputation_score = max(0.0, min(1.0, state.reputation_score + delta))
