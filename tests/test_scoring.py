from app.waf.features import Features
from app.waf.scoring import score


def _feats(**overrides) -> Features:
    base = {
        "max_field_entropy": 0.0,
        "max_field_length": 0,
        "rule_hit_count": 0,
        "max_rule_severity": 0,
        "requests_last_window": 1,
        "unique_endpoints_last_window": 1,
        "reputation_score": 0.0,
    }
    base.update(overrides)
    return Features(**base)


def test_benign_features_score_near_zero():
    result = score(_feats())
    assert 0.0 <= result.score < 0.1


def test_score_is_bounded_between_0_and_1():
    result = score(_feats(max_field_entropy=8, max_field_length=100000,
                           rule_hit_count=10, max_rule_severity=5,
                           requests_last_window=1000, unique_endpoints_last_window=500,
                           reputation_score=1.0))
    assert 0.0 <= result.score < 1.0


def test_score_increases_with_rule_hits():
    low = score(_feats(rule_hit_count=0))
    high = score(_feats(rule_hit_count=3, max_rule_severity=5))
    assert high.score > low.score


def test_top_features_includes_dominant_contributor():
    result = score(_feats(reputation_score=1.0))
    assert "reputation_score" in result.top_features


def test_model_version_is_reported():
    result = score(_feats())
    assert result.model_version


def test_sustained_high_volume_from_one_client_does_not_alone_reach_block_threshold():
    # regression: found via load testing (loadtest/README.md) -- a single
    # legitimate client behind NAT/CDN can generate thousands of requests
    # per window with no attack content at all. Before the log1p fix,
    # requests_last_window was weighted linearly and alone pushed the
    # score to ~1.0, hard-blocking ordinary high-frequency clients.
    result = score(_feats(requests_last_window=5000, unique_endpoints_last_window=3))
    assert result.score < 0.75  # below Policy.ai_block_threshold default


def test_score_scales_sublinearly_with_request_volume():
    low = score(_feats(requests_last_window=10))
    high = score(_feats(requests_last_window=10_000))
    # 1000x more requests should not translate into anywhere near a
    # proportional score increase (log-scaling, not linear).
    assert high.score < low.score * 20
