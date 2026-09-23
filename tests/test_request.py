from app.waf.request import WafRequest


def test_fields_includes_path_and_body():
    req = WafRequest(method="GET", path="/x", client_ip="1.1.1.1", body="payload")
    names = [name for name, _ in req.fields()]
    assert "path" in names
    assert "body" in names


def test_fields_includes_every_query_value_with_prefixed_name():
    req = WafRequest(method="GET", path="/", client_ip="1.1.1.1",
                      query={"tag": ["a", "b"], "id": ["1"]})
    values = [v for name, v in req.fields() if name == "query:tag"]
    assert values == ["a", "b"]  # both repeated values present, not collapsed
    assert ("query:id", "1") in req.fields()


def test_fields_includes_headers_except_authorization_and_cookie():
    req = WafRequest(method="GET", path="/", client_ip="1.1.1.1",
                      headers={"Authorization": "secret", "Cookie": "session=x", "X-Custom": "value"})
    names = [name for name, _ in req.fields()]
    assert "header:X-Custom" in names
    assert "header:Authorization" not in names
    assert "header:Cookie" not in names


def test_fields_header_exclusion_is_case_insensitive():
    req = WafRequest(method="GET", path="/", client_ip="1.1.1.1",
                      headers={"authorization": "secret", "COOKIE": "x"})
    names = [name for name, _ in req.fields()]
    assert not any(n.startswith("header:") for n in names)


def test_fields_on_minimal_request_still_has_path_and_body():
    req = WafRequest(method="GET", path="/", client_ip="1.1.1.1")
    fields = req.fields()
    assert ("path", "/") in fields
    assert ("body", "") in fields
