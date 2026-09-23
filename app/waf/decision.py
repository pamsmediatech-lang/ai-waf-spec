"""Warstwa 4 (spec §6.1 pkt 5, §6.2): Decision Engine.

ponytail: tryb `challenge` (spec §6.2) traktowany jak `block` -- pełny
flow JS-challenge/CAPTCHA to osobna funkcjonalność UI poza zakresem tej
wersji. Dodać renderowanie challenge gdy będzie potrzebny mniej
inwazyjny środek niż twarde blokowanie w strefie niepewności.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .rules import RuleMatch
from .scoring import ScoreResult


class Decision(StrEnum):
    ALLOW = "allow"
    MONITOR = "monitor"
    CHALLENGE = "challenge"
    BLOCK = "block"


@dataclass(frozen=True)
class Policy:
    """Spec §9.2 "konfiguracja jako kod" -- w produkcji ładowana z policy store."""
    critical_rule_severity: int = 5       # trafienie reguły >= ten próg -> block (fail-closed, §13.1)
    ai_block_threshold: float = 0.75
    ai_challenge_threshold: float = 0.45
    ai_monitor_threshold: float = 0.20


@dataclass(frozen=True)
class DecisionResult:
    decision: Decision
    reason: str
    rules_matched: list[str]
    ai_score: float
    ai_top_features: list[str]
    model_version: str


_DEFAULT_POLICY = Policy()


def decide(rule_matches: list[RuleMatch], ai_result: ScoreResult, policy: Policy = _DEFAULT_POLICY) -> DecisionResult:
    rule_ids = [m.rule_id for m in rule_matches]

    critical_hit = any(m.severity >= policy.critical_rule_severity for m in rule_matches)
    if critical_hit:
        return DecisionResult(Decision.BLOCK, "critical_rule_match", rule_ids,
                               ai_result.score, ai_result.top_features, ai_result.model_version)

    if ai_result.score >= policy.ai_block_threshold:
        return DecisionResult(Decision.BLOCK, "ai_score_above_block_threshold", rule_ids,
                               ai_result.score, ai_result.top_features, ai_result.model_version)

    if rule_matches or ai_result.score >= policy.ai_challenge_threshold:
        return DecisionResult(Decision.CHALLENGE, "rule_hit_or_ai_score_in_gray_zone", rule_ids,
                               ai_result.score, ai_result.top_features, ai_result.model_version)

    if ai_result.score >= policy.ai_monitor_threshold:
        return DecisionResult(Decision.MONITOR, "ai_score_above_monitor_threshold", rule_ids,
                               ai_result.score, ai_result.top_features, ai_result.model_version)

    return DecisionResult(Decision.ALLOW, "no_signal", rule_ids,
                           ai_result.score, ai_result.top_features, ai_result.model_version)
