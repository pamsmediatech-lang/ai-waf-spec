"""Stan sesji/klienta w oknie czasowym (spec §5 "feature store online", §7.2).

ponytail: magazyn w pamięci procesu z twardym limitem (LRU eviction),
wystarczający dla jednego węzła inline i testów. Upgrade do
zewnętrznego store (Redis z TTL na kluczu) gdy data plane będzie
skalowany poziomo na wiele instancji dzielących stan -- TTL zastąpi
wtedy ręczną ewikcję poniżej.
"""
from __future__ import annotations

import time
from collections import OrderedDict
from dataclasses import dataclass, field

WINDOW_SECONDS = 60.0

# Twardy limit liczby jednocześnie śledzonych klientów. Bez tego atakujący
# rotujący źródłowy adres IP (lub fałszujący X-Forwarded-For) mógłby
# wyczerpać pamięć samego WAF-a -- WAF nie może być łatwiejszym celem
# DoS niż aplikacja, którą chroni.
DEFAULT_MAX_CLIENTS = 50_000


@dataclass
class ClientState:
    request_times: list[float] = field(default_factory=list)
    endpoints: set[str] = field(default_factory=set)
    reputation_score: float = 0.0  # aktualizowane przez §6.3 (LLM feedback), 0..1


class SessionStore:
    def __init__(self, window_seconds: float = WINDOW_SECONDS, max_clients: int = DEFAULT_MAX_CLIENTS) -> None:
        self._window = window_seconds
        self._max_clients = max_clients
        # OrderedDict + move_to_end na każdym dotknięciu = tania (O(1))
        # kolejka LRU: najdawniej używany klient jest zawsze na początku.
        self._clients: OrderedDict[str, ClientState] = OrderedDict()

    def __len__(self) -> int:
        return len(self._clients)

    def record(self, client_ip: str, path: str, now: float | None = None) -> ClientState:
        now = time.time() if now is None else now
        state = self._clients.get(client_ip)
        if state is None:
            state = ClientState()
            self._clients[client_ip] = state
            self._evict_lru_if_over_capacity()
        self._clients.move_to_end(client_ip)

        state.request_times.append(now)
        state.request_times = [t for t in state.request_times if now - t <= self._window]
        state.endpoints.add(path)
        return state

    def get(self, client_ip: str) -> ClientState:
        state = self._clients.setdefault(client_ip, ClientState())
        self._clients.move_to_end(client_ip)
        self._evict_lru_if_over_capacity()
        return state

    def bump_reputation(self, client_ip: str, delta: float) -> None:
        state = self.get(client_ip)
        state.reputation_score = max(0.0, min(1.0, state.reputation_score + delta))

    def _evict_lru_if_over_capacity(self) -> None:
        while len(self._clients) > self._max_clients:
            self._clients.popitem(last=False)
