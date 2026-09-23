"""Warstwa 0 (spec SPEC.md §6.1): normalizacja wejścia przed dopasowaniem reguł.

Dekoduje wielokrotne url-encoding i normalizuje unicode, żeby utrudnić
obejście reguł przez kodowanie (np. %2527 zamiast ').
"""
from __future__ import annotations

import unicodedata
from urllib.parse import unquote

MAX_DECODE_ROUNDS = 5


def normalize_text(value: str) -> str:
    decoded = value
    for _ in range(MAX_DECODE_ROUNDS):
        next_decoded = unquote(decoded)
        if next_decoded == decoded:
            break
        decoded = next_decoded
    return unicodedata.normalize("NFKC", decoded)
