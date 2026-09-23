# AI-WAF — implementacja Fazy 0 (spec SPEC.md §14)

Standalone reverse proxy (spec §5.3 wariant 4) realizujący pipeline z
§6.1: normalizacja → silnik reguł statycznych → ekstrakcja cech →
heurystyczny AI Scoring Engine → Decision Engine, z pełnym event
loggingiem (§8) i redakcją nagłówków wrażliwych (§11).

## Uruchomienie

```bash
python -m venv .venv
.venv/Scripts/pip install -r requirements.txt   # Windows
# .venv/bin/pip install -r requirements.txt     # Linux/macOS

# chroniona aplikacja nasłuchuje np. na :8000
WAF_BACKEND_URL=http://localhost:8000 .venv/Scripts/python -m uvicorn app.main:app --port 8080
```

## Testy

```bash
.venv/Scripts/python -m pytest -q
```

## Zakres tej wersji vs specyfikacja

Zaimplementowano Fazę 0 + baseline warstwy AI (nie pełny model ML —
patrz `ponytail:` w [app/waf/scoring.py](waf/scoring.py)) i tryb
`challenge` uproszczony do zachowania jak `block` (patrz
[app/waf/decision.py](waf/decision.py)). Fazy 1-4 (shadow rollout,
trenowany model, LLM kontekstowy, pełna automatyzacja) — do zrobienia
zgodnie z SPEC.md §14.
