"""Warstwa 3 (spec §6.1 pkt 4, §7.1): AI Scoring Engine.

ponytail: baseline to przejrzysta ważona heurystyka na cechach z
features.py zamiast wytrenowanego modelu — brak jeszcze oznaczonego
zbioru danych (spec §7.3). Kontrakt (Features -> ScoreResult z top
cechami) jest zaprojektowany tak, żeby podmienić tę funkcję na
faktyczny model (gradient boosting/sieć) bez zmian w decision.py,
zgodnie z FR-13 (rollout modeli bez przestoju).
"""
from __future__ import annotations

from dataclasses import dataclass

from .features import Features

# Wagi kalibrowane ręcznie dla baseline; w produkcyjnym modelu byłyby
# nauczone z danych (spec §7.3) i wersjonowane w model registry (§10.1).
_WEIGHTS: dict[str, float] = {
    "max_field_entropy": 0.12,     # >4.5 bitów/znak sugeruje losowy/obfuskowany payload
    "max_field_length": 0.0005,    # bardzo długie pola są podejrzane
    "rule_hit_count": 0.25,
    "max_rule_severity": 0.15,
    "requests_last_window": 0.01,  # wysoka częstotliwość => możliwy bot/brute force
    "unique_endpoints_last_window": 0.02,  # scraping/enumeracja
    "reputation_score": 0.35,      # zasilane przez feedback LLM, spec §6.3
}
MODEL_VERSION = "heuristic-baseline-v0.1.0"


@dataclass(frozen=True)
class ScoreResult:
    score: float  # 0..1
    top_features: list[str]
    model_version: str


def score(features: Features) -> ScoreResult:
    values = {
        "max_field_entropy": features.max_field_entropy,
        "max_field_length": features.max_field_length,
        "rule_hit_count": features.rule_hit_count,
        "max_rule_severity": features.max_rule_severity,
        "requests_last_window": features.requests_last_window,
        "unique_endpoints_last_window": features.unique_endpoints_last_window,
        "reputation_score": features.reputation_score,
    }
    contributions = {name: _WEIGHTS[name] * val for name, val in values.items()}
    raw = sum(contributions.values())
    normalized = raw / (1.0 + raw)  # kompresja do (0, 1), monotoniczna względem raw

    top = sorted(contributions, key=contributions.get, reverse=True)[:3]
    top = [name for name in top if contributions[name] > 0]

    return ScoreResult(score=round(normalized, 4), top_features=top, model_version=MODEL_VERSION)
