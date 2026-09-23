"""Test obciążeniowy (spec SPEC.md §12.3) -- mierzy dodatkowe opóźnienie
i przepustowość AI-WAF względem gołego backendu (NFR-1/NFR-2).

Użycie -- porównanie baseline vs przez WAF:

    # terminal 1: chroniona aplikacja (baseline)
    .venv/Scripts/python -m uvicorn loadtest.backend_stub:app --port 8001

    # terminal 2: AI-WAF przed nią
    WAF_BACKEND_URL=http://localhost:8001 \
        .venv/Scripts/python -m uvicorn app.main:app --port 8080

    # terminal 3a: baseline (bez WAF, uderz bezpośrednio w :8001)
    .venv/Scripts/python -m locust -f loadtest/locustfile.py \
        --host http://localhost:8001 --headless -u 50 -r 10 -t 30s --csv loadtest/results_baseline

    # terminal 3b: przez WAF (:8080) -- porównaj p50/p95/p99 z powyższym
    .venv/Scripts/python -m locust -f loadtest/locustfile.py \
        --host http://localhost:8080 --headless -u 50 -r 10 -t 30s --csv loadtest/results_waf

Domyślna mieszanka ruchu to ~90% benign / ~10% złośliwy (jeden z
punktów testowych z §12.3: "pod różnym udziałem ruchu złośliwego (0%,
10%, 50%)"); zmień wagi w @task, żeby przetestować inny udział.
"""
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from locust import HttpUser, between, task  # noqa: E402

from ml.dataset import MALICIOUS_PAYLOADS  # noqa: E402 -- reużycie tych samych payloadów co w treningu (spec §7.3)

BENIGN_SEARCH_TERMS = ["laptop bag", "running shoes", "coffee maker", "desk lamp", "winter jacket"]


class WafLoadTestUser(HttpUser):
    wait_time = between(0.01, 0.1)

    @task(30)
    def browse_products(self):
        self.client.get("/products", params={"category": random.choice(["shoes", "bags", "home"])},
                         name="/products")

    @task(20)
    def product_detail(self):
        self.client.get(f"/products/{random.randint(1, 9999)}", name="/products/:id")

    @task(20)
    def search(self):
        self.client.get("/search", params={"q": random.choice(BENIGN_SEARCH_TERMS)}, name="/search")

    @task(20)
    def login(self):
        self.client.post("/login", data="username=demo&password=demo1234", name="/login")

    @task(10)
    def malicious_probe(self):
        category, payload = random.choice(MALICIOUS_PAYLOADS)
        # catch_response: 200 (bez WAF-a, baseline) i 403 (zablokowane
        # przez WAF) są tu oba "sukcesem" -- mierzymy opóźnienie i
        # przepustowość pipeline'u, nie poprawność blokowania (to
        # sprawdzają testy jednostkowe/integracyjne w tests/).
        with self.client.get("/products", params={"id": payload}, name=f"/products?id=<{category}>",
                              catch_response=True) as resp:
            if resp.status_code in (200, 403):
                resp.success()
