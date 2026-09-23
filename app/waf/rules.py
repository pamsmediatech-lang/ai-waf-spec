"""Warstwa 1 (spec SPEC.md §6.1): silnik reguł statycznych, koncepcyjnie zgodny z OWASP CRS.

ponytail: zestaw reguł to reprezentatywny podzbiór klas ataków z FR-3/§1.2,
nie pełny port CRS. Rozszerzać przez dopisanie wpisów do RULES, gdy
pojawią się nowe klasy ataków do wykrycia.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .normalize import normalize_text
from .request import WafRequest


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    pattern: re.Pattern[str]
    severity: int  # 1 (niska) .. 5 (krytyczna)
    scan_headers: bool = True


@dataclass(frozen=True)
class RuleMatch:
    rule_id: str
    category: str
    severity: int
    field: str


RULES: list[Rule] = [
    Rule("942100-sqli-union-select", "sqli",
         re.compile(r"union\s+select", re.IGNORECASE), 5),
    Rule("942101-sqli-boolean", "sqli",
         re.compile(r"(\bor\b|\band\b)\s+['\"]?\s*\w+['\"]?\s*=\s*['\"]?\w+['\"]?", re.IGNORECASE), 5),
    # scan_headers=False: gołe "/*" jest nie do odróżnienia od zwykłych
    # wildcardów MIME w nagłówkach przeglądarki (Accept:
    # "...,image/apng,*/*;q=0.8,application/signed-exchange...",
    # Accept-Encoding z "identity;q=1, *;q=0" itd.) -- każda prawdziwa
    # przeglądarka wysyła takie wartości na co dzień, więc trafienie tej
    # reguły w nagłówku jest w praktyce zawsze fałszywym alarmem, nigdy
    # realnym atakiem (znalezione na żywej przeglądarce uderzającej w WAF
    # chroniący prawdziwą aplikację, nie w syntetycznym teście). W
    # query/body/path (gdzie faktycznie ląduje wstrzyknięty SQL) reguła
    # zostaje aktywna.
    Rule("942102-sqli-comment", "sqli",
         re.compile(r"(--|#)\s*$|/\*(?!\*?$)|;\s*drop\s+table", re.IGNORECASE), 4,
         scan_headers=False),
    Rule("941100-xss-script-tag", "xss",
         re.compile(r"<\s*script\b", re.IGNORECASE), 5),
    Rule("941101-xss-event-handler", "xss",
         re.compile(r"on(error|load|click|mouseover)\s*=", re.IGNORECASE), 4),
    Rule("941102-xss-javascript-uri", "xss",
         re.compile(r"javascript\s*:", re.IGNORECASE), 3),
    Rule("930100-path-traversal", "path_traversal",
         re.compile(r"(\.\./|\.\.\\){2,}|/etc/passwd|\\windows\\system32", re.IGNORECASE), 4),
    Rule("932100-command-injection", "command_injection",
         re.compile(r"(;|\||&&)\s*(cat|ls|whoami|rm|curl|wget|nc)\b", re.IGNORECASE), 5),
    Rule("932101-command-substitution", "command_injection",
         re.compile(r"\$\([^)]+\)|`[^`]+`"), 4),
]


def evaluate(request: WafRequest) -> list[RuleMatch]:
    matches: list[RuleMatch] = []
    for field_name, raw_value in request.fields():
        normalized = normalize_text(raw_value)
        is_header = field_name.startswith("header:")
        for rule in RULES:
            if is_header and not rule.scan_headers:
                continue
            if rule.pattern.search(normalized):
                matches.append(RuleMatch(rule.id, rule.category, rule.severity, field_name))
    return matches
