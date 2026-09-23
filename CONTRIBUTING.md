# Strategia branchowania

Trzy poziomy gałęzi + praca na feature branchach zawsze w osobnym
`git worktree`, żeby główny katalog repo nigdy nie musiał przełączać
kontekstu (i żeby dało się mieć kilka branchy odpalonych/testowanych
równolegle bez `git stash`).

## Gałęzie

```
master        -- zawsze wdrażalny stan; tu żyją tagi/release'y
  └─ integration  -- staging: tu scalają się ukończone feature branche
       └─ feature/<nazwa>   -- pojedyncza zmiana, żyje krótko
       └─ fix/<nazwa>
       └─ docs/<nazwa>
```

- **`master`** -- CI zawsze zielone, historia liniowa (merge tylko z `integration`).
- **`integration`** -- gdzie ląduje ukończona praca zanim trafi do `master`;
  pozwala zebrać kilka feature branchy i sprawdzić, że działają razem,
  zanim cokolwiek dotknie `master`.
- **`feature/<nazwa>` / `fix/<nazwa>` / `docs/<nazwa>`** -- gałąź na
  konkretną zmianę, tworzona z `integration`, mergowana z powrotem do
  `integration` przez PR, usuwana po mergu.

## Workflow: feature branch w osobnym worktree

Nigdy nie robimy `git checkout feature/x` w głównym katalogu repo --
zamiast tego osobny katalog roboczy per branch:

```bash
# nowa praca -- gałąź z integration, osobny worktree
git fetch origin
git worktree add .worktrees/<nazwa> -b feature/<nazwa> origin/integration

cd .worktrees/<nazwa>
# ... praca, commity ...
git push -u origin feature/<nazwa>
# PR: feature/<nazwa> -> integration

# po zmergowaniu PR-a, sprzątanie:
cd ../..
git worktree remove .worktrees/<nazwa>
git branch -d feature/<nazwa>
```

`.worktrees/` jest w `.gitignore` -- to lokalny, tymczasowy katalog
roboczy, nie część repo.

## Release: integration -> master

Gdy `integration` zbierze zestaw gotowych zmian: PR `integration -> master`,
CI musi przejść, merge (nie squash -- chcemy zachować historię
poszczególnych feature branchy w `master`).

## Wyjątki

Commit bezpośrednio na `master` z pominięciem `integration` -- tylko
dla trywialnych poprawek dokumentacji, nigdy dla kodu.

Wcześniejsza historia projektu (do commita `1d8c6c1`) powstała przed
wprowadzeniem tej zasady -- commitowanie prosto na `master`. Nie
przepisujemy jej retroaktywnie; ta strategia obowiązuje od teraz.
