from app.waf.features import _shannon_entropy, extract
from app.waf.request import WafRequest
from app.waf.rules import RuleMatch
from app.waf.session_store import SessionStore


def test_shannon_entropy_of_empty_string_is_zero():
    assert _shannon_entropy("") == 0.0


def test_shannon_entropy_of_repeated_char_is_zero():
    assert _shannon_entropy("aaaaaa") == 0.0


def test_shannon_entropy_of_varied_text_is_positive():
    assert _shannon_entropy("aB3$kZ9!") > 0.0


def test_extract_reflects_rule_hits_and_session_state():
    store = SessionStore()
    req = WafRequest(method="GET", path="/login", client_ip="10.0.0.1")
    matches = [RuleMatch("942100-sqli-union-select", "sqli", 5, "query:id")]

    store.record("10.0.0.1", "/a")
    store.record("10.0.0.1", "/b")
    client_state = store.get("10.0.0.1")

    feats = extract(req, matches, client_state)

    assert feats.rule_hit_count == 1
    assert feats.max_rule_severity == 5
    assert feats.requests_last_window == 2
    assert feats.unique_endpoints_last_window == 2


def test_extract_with_no_rule_matches_has_zero_severity():
    store = SessionStore()
    req = WafRequest(method="GET", path="/", client_ip="10.0.0.2")
    feats = extract(req, [], store.get("10.0.0.2"))
    assert feats.rule_hit_count == 0
    assert feats.max_rule_severity == 0
