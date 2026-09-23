# Test obciążeniowy (spec SPEC.md §12.3)

Mierzy dodatkowe opóźnienie i przepustowość, które AI-WAF dokłada do
gołego backendu (NFR-1: p50≤2ms/p99≤10ms narzutu, NFR-2: ≥10k req/s).

## Uruchomienie

```bash
pip install -r loadtest/requirements.txt

# terminal 1: chroniona aplikacja (baseline, bez WAF)
.venv/Scripts/python -m uvicorn loadtest.backend_stub:app --port 8001

# terminal 2: AI-WAF przed nią
WAF_BACKEND_URL=http://localhost:8001 \
    .venv/Scripts/python -m uvicorn app.main:app --port 8080

# terminal 3a: baseline
.venv/Scripts/python -m locust -f loadtest/locustfile.py \
    --host http://localhost:8001 --headless -u 30 -r 10 -t 15s

# terminal 3b: przez WAF -- porównaj p50/p95/p99 z powyższym
.venv/Scripts/python -m locust -f loadtest/locustfile.py \
    --host http://localhost:8080 --headless -u 30 -r 10 -t 15s
```

**Restartuj proces WAF między przebiegami** (`SessionStore` jest w
pamięci procesu -- świeży proces = świeży stan sesji/reputacji).

## Realne znalezisko z tego testu

Pierwszy przebieg (przed poprawką) pokazał, że **~90% ruchu benign
dostawało 403**. Przyczyna: wszyscy wirtualni użytkownicy Locusta
uderzają z jednej maszyny, więc `SessionStore` widzi ich jako **jeden
`client_ip`**. Cecha `requests_last_window` w
[app/waf/scoring.py](../app/waf/scoring.py) była ważona liniowo
(`0.01 * liczba_żądań`) -- przy kilku tysiącach żądań w oknie 60s z
jednego adresu ta jedna cecha sama przebijała próg blokady, niezależnie
od treści żądania. To nie był artefakt tylko tego testu: **każdy
legalny klient za NAT-em/CDN-em, który dzieli widoczny adres IP z wieloma
innymi użytkownikami, byłby tak samo blokowany na produkcji.**

Naprawa: cechy typu "licznik" bez naturalnej górnej granicy
(`requests_last_window`, `unique_endpoints_last_window`,
`max_field_length`) są teraz skalowane przez `log1p()` przed
zważeniem (`_LOG_SCALED_FEATURES` w `scoring.py`), więc rosną
podliniowo zamiast wprost proporcjonalnie -- patrz testy regresyjne
`test_sustained_high_volume_from_one_client_does_not_alone_reach_block_threshold`
i `test_score_scales_sublinearly_with_request_volume` w
`tests/test_scoring.py`.

## Znana granica tej metodyki testowej (nie kodu)

Nawet po poprawce: jeśli jeden proces Locusta na jednej maszynie
utrzyma wystarczająco wysoki, długotrwały wolumen do jednego
`client_ip`, w końcu i tak trafi strefę `challenge`/`block` -- **to jest
zamierzone działanie** warstwy behawioralnej (spec §7.1 "Traffic
anomaly": wykrywanie wolumetrycznego/botowego ruchu), nie błąd. Sam
Locust uruchomiony masowo z jednego adresu IP wygląda z perspektywy
WAF-a dokładnie jak wolumetryczny bot, którego ta warstwa ma wykrywać.

Żeby zmierzyć czysty narzut latencji (NFR-1) bez wchodzenia w tę
strefę: trzymaj `-u`/czas trwania na tyle niskie, żeby
`requests_last_window` nie eskalował w trakcie przebiegu, albo
uruchamiaj Locusta rozproszony (`--processes`) z wielu adresów IP,
żeby odzwierciedlić realny ruch od wielu klientów -- to dokładnie
scenariusz `NFR-2`/`§12.3` (test pod różnym wolumenem), a nie coś, co
warto obchodzić fałszując tożsamość klienta w samym WAF-ie.
