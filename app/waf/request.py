"""Reprezentacja żądania używana przez wszystkie warstwy pipeline'u (spec §6.1)."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class WafRequest:
    method: str
    path: str
    client_ip: str
    headers: dict[str, str] = field(default_factory=dict)
    query: dict[str, list[str]] = field(default_factory=dict)
    body: str = ""

    def fields(self) -> list[tuple[str, str]]:
        """Wszystkie pola tekstowe żądania jako (nazwa_pola, wartość) do skanowania regułami."""
        out: list[tuple[str, str]] = [("path", self.path), ("body", self.body)]
        for name, values in self.query.items():
            for v in values:
                out.append((f"query:{name}", v))
        for name, v in self.headers.items():
            if name.lower() not in {"authorization", "cookie"}:
                out.append((f"header:{name}", v))
        return out
