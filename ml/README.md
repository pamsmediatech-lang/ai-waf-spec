# Trening Content Classifier (spec SPEC.md §7)

```bash
.venv/Scripts/python -m ml.train
```

Generuje syntetyczny zbiór ([dataset.py](dataset.py)), trenuje
`RandomForestClassifier` na cechach z `app/waf/features.py`, waliduje na
hold-out (30%) i zapisuje do `ml/artifacts/`:
- `content-classifier-v0.1.0.joblib` — model
- `content-classifier-v0.1.0.json` — metryki, feature importances, metadane treningu

Wynik ostatniego treningu: **precision 0.973, recall 1.000, f1 0.986**
(brama jakości w `train.py`: recall ≥ 0.95, precision ≥ 0.90).

## Dlaczego zbiór nie jest trywialny

Pierwsza wersja zbioru dawała **100% na wszystkich metrykach** — podejrzanie
dobry wynik, bo każda złośliwa próbka trafiała też regułę statyczną, więc
model uczył się wyłącznie „czy `rule_hit_count > 0`”, nie realnej treści
ataku. Dodałem dwie trudniejsze klasy w [dataset.py](dataset.py), które
regex z `rules.py` **celowo omija** (`rule_hit_count == 0`):

- **ewazje** — rozbite słowa kluczowe (`UN/**/ION SEL/**/ECT`), overlong
  UTF-8 (`%c0%af` zamiast `/`), separator command injection przez newline
  zamiast `;`/`|`/`&&`,
- **brute force** — atak czysto behawioralny (dziesiątki prób logowania
  do `/login` bez żadnego payloadu injection) — klasa, której reguły
  statyczne z definicji nie widzą.

Po tej zmianie metryki spadły z 1.00/1.00 do 0.973/1.00 — model myli
część benignych „power userów" (dużo żądań do jednego endpointu) z
brute force, bo obecny zestaw cech (`features.py`) nie odróżnia tych
dwóch przypadków. To prawdziwe, udokumentowane ograniczenie, nie ukryty
błąd — patrz `ponytail:` w [dataset.py](dataset.py).

## Podmiana scorera w pipeline

[app/waf/ml_scorer.py](../app/waf/ml_scorer.py) implementuje ten sam
kontrakt `Features -> ScoreResult` co heurystyka w
[app/waf/scoring.py](../app/waf/scoring.py) (FR-13) — `TrainedScorer.load()`
wczytuje artefakt i podłącza się do `decision.py` bez żadnych zmian tam.
Domyślnie pipeline (`app/waf/pipeline.py`) nadal używa heurystyki —
świadomie, bo model jest trenowany na danych syntetycznych (patrz
`ponytail:` w `dataset.py`), więc zgodnie z planem wdrożenia (SPEC.md
§10.2) najpierw powinien przejść tryb shadow na prawdziwym ruchu, zanim
zastąpi baseline.
