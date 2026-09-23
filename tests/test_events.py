from app.waf.decision import Decision, DecisionResult
from app.waf.events import build_event
from app.waf.request import WafRequest


def test_authorization_and_cookie_headers_are_redacted():
    req = WafRequest(
        method="POST",
        path="/login",
        client_ip="203.0.113.10",
        headers={"Authorization": "Bearer secret-token", "Cookie": "session=abc", "User-Agent": "pytest"},
    )
    result = DecisionResult(Decision.ALLOW, "no_signal", [], 0.0, [], "test-v1")
    event = build_event(req, result, latency_ms=1.23)

    assert event.headers_redacted["Authorization"] == "<redacted>"
    assert event.headers_redacted["Cookie"] == "<redacted>"
    assert event.headers_redacted["User-Agent"] == "pytest"


def test_event_has_unique_id_and_matches_decision():
    req = WafRequest(method="GET", path="/", client_ip="127.0.0.1")
    result = DecisionResult(Decision.BLOCK, "critical_rule_match", ["942100-sqli-union-select"],
                             0.9, ["rule_hit_count"], "test-v1")
    event = build_event(req, result, latency_ms=2.0)

    assert event.decision == "block"
    assert event.rules_matched == ["942100-sqli-union-select"]
    assert event.event_id
    assert event.body_size == 0


def test_body_size_reflects_utf8_byte_length():
    req = WafRequest(method="POST", path="/", client_ip="127.0.0.1", body="héllo")
    result = DecisionResult(Decision.ALLOW, "no_signal", [], 0.0, [], "test-v1")
    event = build_event(req, result, latency_ms=1.0)
    assert event.body_size == len("héllo".encode())
