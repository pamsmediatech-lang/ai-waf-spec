# AI-WAF — Web Application Firewall wspomagany AI (czas rzeczywisty)

Silnik reguł statycznych (OWASP CRS-like) + warstwa AI (heurystyka bazowa,
z kontraktem gotowym na podmianę na wytrenowany model) do wykrywania
i blokowania ataków webowych w czasie rzeczywistym, inline, na ścieżce
żądania.

## Status

**Faza 0 (fundament) wdrożona i przetestowana**: silnik reguł, AI Scoring
Engine, Decision Engine, reverse proxy, pipeline pełnej detekcji. 97 testów,
CI zielone (pytest + ruff). Zweryfikowane na żywej aplikacji (nie tylko
testach syntetycznych) — dwa realne false positive znalezione i naprawione
po drodze, patrz historia commitów.

| Co | Gdzie |
|---|---|
| Specyfikacja | [SPEC.md](SPEC.md) |
| Implementacja | [app/](app/README.md) |
| Trening modelu ML | [ml/](ml/README.md) |
| Test obciążeniowy | [loadtest/](loadtest/README.md) |
| Notebooki Colab (prototyp LLM, treningu) | [notebooks/](notebooks) |
| Roadmap / co dalej | [ROADMAP.md](ROADMAP.md) |
| Strategia branchowania | [CONTRIBUTING.md](CONTRIBUTING.md) |

## Szybki start

```bash
python -m venv .venv
.venv/Scripts/pip install -r requirements.txt   # Windows
.venv/Scripts/python -m pytest -q
```

Uruchomienie jako proxy przed chronioną aplikacją: patrz [app/README.md](app/README.md).
