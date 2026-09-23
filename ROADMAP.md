# Roadmap

Plan wdrożenia z [SPEC.md §14](SPEC.md#14-plan-wdrożenia-fazy), rozbity na
[issues](https://github.com/pamsmediatech-lang/ai-waf-spec/issues) i
[milestone'y](https://github.com/pamsmediatech-lang/ai-waf-spec/milestones)
na GitHubie. Ten plik to punkt wejścia — szczegóły i dyskusja żyją w issues,
nie tu.

## Zrobione — Faza 0: Fundament

Silnik reguł statycznych, heurystyczny AI Scoring Engine, Decision Engine,
reverse proxy, 97 testów, CI (pytest + ruff), zweryfikowane na żywej
aplikacji (HORNY_JAIL). Szczegóły: [app/README.md](app/README.md).

## [Faza 1 — AI shadow mode](https://github.com/pamsmediatech-lang/ai-waf-spec/milestone/1)

Cel: prawdziwy wytrenowany model oceniający ruch produkcyjny równolegle do
heurystyki, bez wpływu na decyzje.

- [#7](https://github.com/pamsmediatech-lang/ai-waf-spec/issues/7) Zastąp syntetyczny dataset prawdziwymi danymi
- [#8](https://github.com/pamsmediatech-lang/ai-waf-spec/issues/8) Wdróż TrainedScorer w trybie shadow
- [#9](https://github.com/pamsmediatech-lang/ai-waf-spec/issues/9) Automatyczny retraining trigger na drift
- [#10](https://github.com/pamsmediatech-lang/ai-waf-spec/issues/10) Rozszerz testy odporności na obejścia

## [Faza 2 — AI canary/enforce](https://github.com/pamsmediatech-lang/ai-waf-spec/milestone/2)

Cel: model aktywnie wpływa na decyzje, najpierw na części ruchu, z
automatycznym rollbackiem.

- [#11](https://github.com/pamsmediatech-lang/ai-waf-spec/issues/11) Automatyzacja canary rollout z rollbackiem
- [#12](https://github.com/pamsmediatech-lang/ai-waf-spec/issues/12) Prawdziwy load test potwierdzający NFR-1/NFR-2
- [#13](https://github.com/pamsmediatech-lang/ai-waf-spec/issues/13) Tryb `challenge` zamiast twardego `block`
- [#14](https://github.com/pamsmediatech-lang/ai-waf-spec/issues/14) Migracja SessionStore do Redis

## [Faza 3 — LLM kontekstowy + reputacja](https://github.com/pamsmediatech-lang/ai-waf-spec/milestone/3)

Cel: głębsza analiza niejednoznacznych/obfuskowanych payloadów poza ścieżką
krytyczną, zasilająca reputację sesji.

- [#15](https://github.com/pamsmediatech-lang/ai-waf-spec/issues/15) Zintegruj LLM z produkcyjnym pipeline'em
- [#16](https://github.com/pamsmediatech-lang/ai-waf-spec/issues/16) Rozstrzygnij hosting LLM: lokalny vs zewnętrzny
- [#17](https://github.com/pamsmediatech-lang/ai-waf-spec/issues/17) Sprzężenie zwrotne LLM → reputacja sesji

## [Faza 4 — Pełna automatyzacja](https://github.com/pamsmediatech-lang/ai-waf-spec/milestone/4)

Cel: zarządzanie, obserwowalność i cykl retraining→rollback bez ręcznej
interwencji poza zatwierdzeniem.

- [#18](https://github.com/pamsmediatech-lang/ai-waf-spec/issues/18) Management API
- [#19](https://github.com/pamsmediatech-lang/ai-waf-spec/issues/19) RBAC + OIDC/mTLS
- [#20](https://github.com/pamsmediatech-lang/ai-waf-spec/issues/20) Eksport metryk Prometheus + dashboard SOC
- [#21](https://github.com/pamsmediatech-lang/ai-waf-spec/issues/21) Domknij cykl retraining→rollback

## Backlog (bez przypisanej fazy)

Ważne, ale nie blokują żadnej konkretnej fazy — do podjęcia gdy pojawi się
okazja albo presja (np. realny incydent).

- [#22](https://github.com/pamsmediatech-lang/ai-waf-spec/issues/22) Per-sesja identyfikator klienta zamiast czystego IP
- [#23](https://github.com/pamsmediatech-lang/ai-waf-spec/issues/23) RODO: prawo do usunięcia danych z logów
- [#24](https://github.com/pamsmediatech-lang/ai-waf-spec/issues/24) Wariant wdrożenia data plane produkcyjnie
- [#25](https://github.com/pamsmediatech-lang/ai-waf-spec/issues/25) Zgodność z normą (PCI-DSS/ISO27001)
