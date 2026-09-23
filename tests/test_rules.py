import pytest

from app.waf.request import WafRequest
from app.waf.rules import evaluate
from ml.dataset import EVASIVE_PAYLOADS


def _req(**kwargs) -> WafRequest:
    defaults = {"method": "GET", "path": "/", "client_ip": "127.0.0.1"}
    defaults.update(kwargs)
    return WafRequest(**defaults)


def test_benign_request_has_no_matches():
    req = _req(path="/products", query={"category": ["shoes"]})
    assert evaluate(req) == []


def test_sqli_union_select_detected():
    req = _req(query={"id": ["1 UNION SELECT username, password FROM users"]})
    matches = evaluate(req)
    assert any(m.rule_id == "942100-sqli-union-select" for m in matches)


def test_sqli_boolean_detected():
    req = _req(query={"id": ["1' OR '1'='1"]})
    matches = evaluate(req)
    assert any(m.category == "sqli" for m in matches)


def test_xss_script_tag_detected():
    req = _req(body="<script>alert(document.cookie)</script>")
    matches = evaluate(req)
    assert any(m.rule_id == "941100-xss-script-tag" for m in matches)


def test_xss_event_handler_detected():
    req = _req(body='<img src=x onerror=alert(1)>')
    matches = evaluate(req)
    assert any(m.category == "xss" for m in matches)


def test_path_traversal_detected():
    req = _req(path="/files/../../../../etc/passwd")
    matches = evaluate(req)
    assert any(m.category == "path_traversal" for m in matches)


def test_command_injection_detected():
    req = _req(query={"host": ["8.8.8.8; cat /etc/passwd"]})
    matches = evaluate(req)
    assert any(m.category == "command_injection" for m in matches)


def test_double_encoded_sqli_detected_via_normalization():
    req = _req(query={"id": ["1%2520UNION%2520SELECT%2520pass"]})
    matches = evaluate(req)
    assert any(m.rule_id == "942100-sqli-union-select" for m in matches)


def test_realistic_chrome_accept_header_is_not_flagged_as_sqli_comment():
    # regression: found via a real browser hitting the WAF, not synthetic
    # data. A real Chrome navigation Accept header contains "*/*" in the
    # MIDDLE of the value (not at the end like the earlier "Accept: */*"
    # fix handled), followed by more MIME ranges -- e.g.
    # "...,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7".
    # The old /\*(?!\*?$) guard only protected "*/*" when it was the
    # entire remainder of the string, so this realistic header still
    # tripped 942102-sqli-comment on every single real browser request.
    accept = ("text/html,application/xhtml+xml,application/xml;q=0.9,"
              "image/avif,image/webp,image/apng,*/*;q=0.8,"
              "application/signed-exchange;v=b3;q=0.7")
    req = _req(headers={"Accept": accept})
    assert evaluate(req) == []


def test_authorization_and_cookie_headers_not_scanned():
    req = _req(headers={"Authorization": "Bearer <script>", "Cookie": "session=<script>"})
    assert evaluate(req) == []


def test_case_insensitive_matching():
    req = _req(body="<ScRiPt>alert(1)</ScRiPt>")
    matches = evaluate(req)
    assert any(m.category == "xss" for m in matches)


def test_windows_style_path_traversal_detected():
    req = _req(path="..\\..\\..\\windows\\system32\\config\\sam")
    matches = evaluate(req)
    assert any(m.category == "path_traversal" for m in matches)


def test_command_substitution_backtick_detected():
    req = _req(body="test`whoami`")
    matches = evaluate(req)
    assert any(m.rule_id == "932101-command-substitution" for m in matches)


def test_command_substitution_dollar_paren_detected():
    req = _req(body="$(rm -rf /)")
    matches = evaluate(req)
    assert any(m.rule_id == "932101-command-substitution" for m in matches)


def test_drop_table_detected():
    req = _req(query={"id": ["1'; DROP TABLE users; --"]})
    matches = evaluate(req)
    assert any(m.category == "sqli" for m in matches)


# Regression lock-in for the known, documented evasion gap (spec §7.5):
# ml.dataset.EVASIVE_PAYLOADS are DESIGNED to slip past the current
# regex rules -- tested by importing that exact list rather than
# duplicating the strings here, so the two can't drift apart. If one of
# these starts matching, that's not automatically a bug in rules.py --
# it means this specific evasion example needs a fresh, harder payload
# so the ML/LLM tests still exercise a real gap (this already happened
# once: two of the original examples turned out to trip unrelated
# rules -- see the ponytail notes in ml/dataset.py).
@pytest.mark.parametrize("category,payload", EVASIVE_PAYLOADS)
def test_evasive_payload_produces_no_rule_matches(category, payload):
    req = _req(query={"x": [payload]})
    assert evaluate(req) == [], f"{category} evasion payload {payload!r} unexpectedly matched a rule"
