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


@dataclass(frozen=True)
class RuleMatch:
    rule_id: str
    category: str
    severity: int
    field: str


RULES: list[Rule] = [
    Rule("942100-sqli-union-select", "sqli",
         re.compile(r"union\s+select", re.I), 5),
    Rule("942101-sqli-boolean", "sqli",
         re.compile(r"(\bor\b|\band\b)\s+['\"]?\s*\w+['\"]?\s*=\s*['\"]?\w+['\"]?", re.I), 5),
    # /\*(?!\*?$) unika FP na standardowym nagłówku Accept: */* (zawiera
    # "/*" zakończone tylko gwiazdką/końcem stringa), a wciąż łapie realne
    # komentarze SQL jak /**/ czy /*!50000union*/.
    Rule("942102-sqli-comment", "sqli",
         re.compile(r"(--|#)\s*$|/\*(?!\*?$)|;\s*drop\s+table", re.I), 4),
    Rule("941100-xss-script-tag", "xss",
         re.compile(r"<\s*script\b", re.I), 5),
    Rule("941101-xss-event-handler", "xss",
         re.compile(r"on(error|load|click|mouseover)\s*=", re.I), 4),
    Rule("941102-xss-javascript-uri", "xss",
         re.compile(r"javascript\s*:", re.I), 3),
    Rule("930100-path-traversal", "path_traversal",
         re.compile(r"(\.\./|\.\.\\){2,}|/etc/passwd|\\windows\\system32", re.I), 4),
    Rule("932100-command-injection", "command_injection",
         re.compile(r"(;|\||&&)\s*(cat|ls|whoami|rm|curl|wget|nc)\b", re.I), 5),
    Rule("932101-command-substitution", "command_injection",
         re.compile(r"\$\([^)]+\)|`[^`]+`"), 4),
]


def evaluate(request: WafRequest) -> list[RuleMatch]:
    matches: list[RuleMatch] = []
    for field_name, raw_value in request.fields():
        normalized = normalize_text(raw_value)
        for rule in RULES:
            if rule.pattern.search(normalized):
                matches.append(RuleMatch(rule.id, rule.category, rule.severity, field_name))
    return matches
