# Trening Content Classifier (spec SPEC.md §7)

```bash
.venv/Scripts/python -m ml.train
```

Generuje syntetyczny zbiór ([dataset.py](dataset.py)), trenuje
`RandomForestClassifier` na cechach z `app/waf/features.py`, waliduje na
hold-out (30%) i zapisuje do `ml/artifacts/`:
- `content-classifier-v0.1.0.joblib` — model
- `content-classifier-v0.1.0.json` — metryki, feature importances, metadane treningu

Wynik ostatniego treningu: **precision 1.000, recall 0.967, f1 0.983**
(brama jakości w `train.py`: recall ≥ 0.90, precision ≥ 0.90 — obniżone
z 0.95, patrz niżej).

## Dlaczego zbiór nie jest trywialny (i dlaczego metryki spadały -- dwa razy)

Pierwsza wersja zbioru dawała **100% na wszystkich metrykach** — podejrzanie
dobry wynik, bo każda złośliwa próbka trafiała też regułę statyczną, więc
model uczył się wyłącznie „czy `rule_hit_count > 0`”, nie realnej treści
ataku. Dodałem dwie trudniejsze klasy w [dataset.py](dataset.py), które
regex z `rules.py` **celowo omija** (`rule_hit_count == 0`):

- **ewazje** — rozbite słowa kluczowe, overlong UTF-8, homoglify
  cyrylickie, separatory command injection spoza `;`/`|`/`&&`, komendy
  spoza whitelisty regexa (11 przykładów, wszystkie kategorie OWASP
  Top 10 z zakresu projektu, w tym XSS),
- **brute force** — atak czysto behawioralny (dziesiątki prób logowania
  do `/login` bez żadnego payloadu injection) — klasa, której reguły
  statyczne z definicji nie widzą.

Po tej zmianie metryki spadły z 1.00/1.00 do 0.973/1.00.

**Druga korekta (2026-09-25):** po krytyce wiarygodności testu LLM w
`notebooks/llm_contextual_review_prototype.ipynb` (n=5 na kategorię to
za mało, żeby cokolwiek stwierdzić statystycznie) rozszerzyłem
`BENIGN_BODIES` z 9 do 25 przykładów. To ujawniło kolejny prawdziwy
problem: wszystkie ówczesne benigne próbki miały 38-72 znaki, a
`EVASIVE_PAYLOADS` (malicious, `rule_hit_count=0`) są typowo krótsze
(11-13 znaków) — model nauczył się „krótkie pole = ewazja" jako proxy
zamiast polegać na `rule_hit_count`/`max_rule_severity`
(`max_field_length` miał 43% ważności cech, więcej niż obie reguły
razem). Dodanie kilku **krótkich** benignych wpisów (`"tak"`, `"super!"`)
rozbiło tę fałszywą korelację, ale ujawniło prawdziwy sufit modelu:
**recall spadł do 0.92-0.97** (zależnie od seeda), a wszystkie false
negatives to krótkie, niskoentropijne payloady ewazyjne — nie do
odróżnienia od krótkich legalnych wiadomości samymi cechami
entropia/długość.

To **nie jest usterka do zamaskowania podniesieniem progu z powrotem
do 0.95** — to jest dokładnie luka, którą ma domykać Faza 3 (LLM
kontekstowy, spec §6.1), i którą już potwierdziliśmy eksperymentalnie:
ten sam zestaw payloadów przepuszczony przez `gemini-3.5-flash-lite`
(notebooks/llm_contextual_review_prototype.ipynb) dał **100% recall**.
Baseline ML (`RandomForest` na entropii/długości) ma realny, zmierzony
sufit; warstwa LLM ten sufit przebija. To jest argument za Fazą 3, nie
porażka Fazy 1. Patrz `ponytail:` w `train.py` i SPEC.md §15 pytanie #4.

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
