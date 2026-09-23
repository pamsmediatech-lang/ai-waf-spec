# Strategia branchowania

Projekt solowy (praca inżynierska), bez recenzenta — ale historia gita ma
to odzwierciedlać jako świadomą decyzję, nie przypadek.

**GitHub Flow, uproszczony do jednej osoby:**

1. `master` jest zawsze wdrażalny (testy przechodzą, CI zielone).
2. Każda zmiana funkcjonalna dostaje krótkotrwały branch:
   `feature/<krótki-opis>`, `fix/<krótki-opis>`, `docs/<krótki-opis>`.
3. Branch trafia do `master` przez Pull Request, nawet jeśli
   zatwierdzany samodzielnie — PR daje: opis zmiany w jednym miejscu,
   uruchomienie CI przed mergem, i czytelną historię (`squash and merge`)
   zamiast serii poprawkowych commitów.
4. Branch po zmergowaniu jest usuwany.
5. Commity bezpośrednio na `master` z pominięciem PR — tylko dla
   trywialnych poprawek dokumentacji, nigdy dla kodu.

Wcześniejsza historia projektu (do commita `1d8c6c1`) powstała bez tej
zasady — commitowanie prosto na `master`. Nie przepisujemy jej retroaktywnie
(fałszowanie historii gita byłoby gorsze niż przyznanie się, że reguła
weszła w życie w trakcie projektu); ta strategia obowiązuje od teraz.
