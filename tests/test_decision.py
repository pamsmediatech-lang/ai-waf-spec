from app.waf.decision import Decision, Policy, decide
from app.waf.rules import RuleMatch
from app.waf.scoring import ScoreResult


def _score(value: float, top=None) -> ScoreResult:
    return ScoreResult(score=value, top_features=top or [], model_version="test-v1")


def test_no_signal_allows():
    result = decide([], _score(0.0))
    assert result.decision == Decision.ALLOW


def test_critical_rule_blocks_even_with_low_ai_score():
    matches = [RuleMatch("942100-sqli-union-select", "sqli", 5, "query:id")]
    result = decide(matches, _score(0.0))
    assert result.decision == Decision.BLOCK
    assert result.reason == "critical_rule_match"


def test_high_ai_score_blocks_without_rule_hit():
    result = decide([], _score(0.9))
    assert result.decision == Decision.BLOCK
    assert result.reason == "ai_score_above_block_threshold"


def test_low_severity_rule_hit_triggers_challenge_not_block():
    matches = [RuleMatch("941102-xss-javascript-uri", "xss", 3, "query:url")]
    result = decide(matches, _score(0.1))
    assert result.decision == Decision.CHALLENGE


def test_mid_ai_score_without_rules_is_monitor():
    result = decide([], _score(0.3))
    assert result.decision == Decision.MONITOR


def test_policy_thresholds_are_configurable():
    strict_policy = Policy(ai_block_threshold=0.2)
    result = decide([], _score(0.25), strict_policy)
    assert result.decision == Decision.BLOCK


def test_ai_score_exactly_at_block_threshold_blocks():
    policy = Policy()  # default ai_block_threshold=0.75
    result = decide([], _score(policy.ai_block_threshold))
    assert result.decision == Decision.BLOCK


def test_ai_score_just_below_block_threshold_does_not_block():
    policy = Policy()
    result = decide([], _score(policy.ai_block_threshold - 0.0001))
    assert result.decision != Decision.BLOCK


def test_ai_score_exactly_at_challenge_threshold_challenges():
    policy = Policy()  # default ai_challenge_threshold=0.45
    result = decide([], _score(policy.ai_challenge_threshold))
    assert result.decision == Decision.CHALLENGE


def test_rule_severity_exactly_at_critical_threshold_blocks():
    policy = Policy()  # default critical_rule_severity=5
    matches = [RuleMatch("test-rule", "test", policy.critical_rule_severity, "body")]
    result = decide(matches, _score(0.0), policy)
    assert result.decision == Decision.BLOCK


def test_rule_severity_one_below_critical_threshold_does_not_auto_block():
    policy = Policy()
    matches = [RuleMatch("test-rule", "test", policy.critical_rule_severity - 1, "body")]
    result = decide(matches, _score(0.0), policy)
    assert result.decision != Decision.BLOCK


def test_decision_result_carries_explainability_data():
    matches = [RuleMatch("942100-sqli-union-select", "sqli", 5, "query:id")]
    result = decide(matches, _score(0.5, top=["rule_hit_count"]))
    assert result.rules_matched == ["942100-sqli-union-select"]
    assert result.ai_top_features == ["rule_hit_count"]
