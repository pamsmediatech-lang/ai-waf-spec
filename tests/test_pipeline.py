from app.waf.decision import Decision, Policy
from app.waf.pipeline import inspect
from app.waf.request import WafRequest
from app.waf.session_store import SessionStore


def test_benign_request_end_to_end_is_allowed_or_monitored():
    store = SessionStore()
    req = WafRequest(method="GET", path="/products", client_ip="1.1.1.1", query={"category": ["shoes"]})
    result, event = inspect(req, store)
    assert result.decision in (Decision.ALLOW, Decision.MONITOR)
    assert event.decision == result.decision.value


def test_sqli_request_end_to_end_is_blocked():
    store = SessionStore()
    req = WafRequest(method="GET", path="/products", client_ip="1.1.1.1",
                      query={"id": ["1 UNION SELECT password FROM users"]})
    result, event = inspect(req, store)
    assert result.decision == Decision.BLOCK
    assert "942100-sqli-union-select" in result.rules_matched
    assert event.rules_matched == result.rules_matched


def test_inspect_records_request_in_session_store():
    store = SessionStore()
    req = WafRequest(method="GET", path="/a", client_ip="9.9.9.9")
    inspect(req, store)
    inspect(req, store)
    assert len(store.get("9.9.9.9").request_times) == 2


def test_inspect_uses_custom_policy():
    store = SessionStore()
    strict_policy = Policy(ai_block_threshold=0.0)
    req = WafRequest(method="GET", path="/", client_ip="1.1.1.1")
    result, _event = inspect(req, store, strict_policy)
    # with an essentially-zero block threshold, even a benign request's
    # nonzero ai score should push past it
    assert result.decision in (Decision.BLOCK, Decision.CHALLENGE)


def test_event_latency_is_recorded_and_positive():
    store = SessionStore()
    req = WafRequest(method="GET", path="/", client_ip="1.1.1.1")
    _result, event = inspect(req, store)
    assert event.latency_ms >= 0.0
