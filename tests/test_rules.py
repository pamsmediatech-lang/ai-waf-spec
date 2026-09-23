from app.waf.request import WafRequest
from app.waf.rules import evaluate


def _req(**kwargs) -> WafRequest:
    defaults = dict(method="GET", path="/", client_ip="127.0.0.1")
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


def test_authorization_and_cookie_headers_not_scanned():
    req = _req(headers={"Authorization": "Bearer <script>", "Cookie": "session=<script>"})
    assert evaluate(req) == []
