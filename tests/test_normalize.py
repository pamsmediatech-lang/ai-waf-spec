from app.waf.normalize import normalize_text


def test_plain_text_unchanged():
    assert normalize_text("hello world") == "hello world"


def test_single_url_decode():
    assert normalize_text("%27%20OR%20%271%27%3D%271") == "' OR '1'='1"


def test_double_url_decode():
    # %2527 -> %27 -> '
    assert normalize_text("%2527") == "'"


def test_stops_when_no_further_decoding_possible():
    # no percent-encoding present: should return unchanged, not loop
    assert normalize_text("100% sure") == "100% sure"
