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


def test_entropy_and_length_ignore_headers_not_just_query_body_path():
    # regression: found via a real browser hitting the WAF (not synthetic
    # data). A standard Chrome Accept header ("text/html,application/
    # xhtml+xml,...,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    # 137 chars) has enough entropy/length on its own to push the AI
    # score into the challenge zone (0.4792 >= 0.45 threshold) for EVERY
    # normal browser request, purely from header fingerprinting text that
    # has nothing to do with injection payloads. Entropy/length features
    # exist to catch obfuscated attacker-controlled input in query/body/
    # path, not to fingerprint browser negotiation headers.
    store = SessionStore()
    long_benign_header = "text/html,application/xhtml+xml,application/xml;q=0.9," + "a,b,c,d,e," * 10
    req = WafRequest(method="GET", path="/", client_ip="10.0.0.3",
                      headers={"Accept": long_benign_header})
    feats = extract(req, [], store.get("10.0.0.3"))
    assert feats.max_field_entropy == 0.0  # only "/" (path) and "" (body) are scanned
    assert feats.max_field_length == 1


def test_entropy_and_length_still_reflect_a_suspicious_query_value():
    store = SessionStore()
    req = WafRequest(method="GET", path="/", client_ip="10.0.0.4",
                      query={"id": ["aB3$kZ9!obfuscated_payload_here"]},
                      headers={"Accept": "*/*"})
    feats = extract(req, [], store.get("10.0.0.4"))
    assert feats.max_field_entropy > 0.0
    assert feats.max_field_length == len("aB3$kZ9!obfuscated_payload_here")
