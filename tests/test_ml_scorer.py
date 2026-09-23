import pytest

from app.waf.decision import decide
from app.waf.features import Features
from app.waf.ml_scorer import ModelUnavailable, TrainedScorer
from app.waf.rules import RuleMatch
from ml.train import save_artifacts, train_and_evaluate


@pytest.fixture()
def trained_scorer(tmp_path) -> TrainedScorer:
    result = train_and_evaluate(n_benign=150, n_malicious=150, seed=5)
    save_artifacts(result["model"], result["metadata"], artifacts_dir=tmp_path)
    return TrainedScorer.load(result["metadata"]["model_version"], artifacts_dir=tmp_path)


def test_load_raises_model_unavailable_when_artifact_missing(tmp_path):
    with pytest.raises(ModelUnavailable):
        TrainedScorer.load("nonexistent-model-v9.9.9", artifacts_dir=tmp_path)


def test_trained_scorer_returns_score_result_contract(trained_scorer: TrainedScorer):
    benign_feats = Features(max_field_entropy=1.0, max_field_length=10, rule_hit_count=0,
                             max_rule_severity=0, requests_last_window=1,
                             unique_endpoints_last_window=1, reputation_score=0.0)
    result = trained_scorer.score(benign_feats)
    assert 0.0 <= result.score <= 1.0
    assert result.top_features
    assert result.model_version == "content-classifier-v0.1.0"


def test_trained_scorer_scores_obvious_attack_higher_than_benign(trained_scorer: TrainedScorer):
    benign_feats = Features(max_field_entropy=2.0, max_field_length=15, rule_hit_count=0,
                             max_rule_severity=0, requests_last_window=1,
                             unique_endpoints_last_window=1, reputation_score=0.0)
    attack_feats = Features(max_field_entropy=4.0, max_field_length=60, rule_hit_count=1,
                             max_rule_severity=5, requests_last_window=1,
                             unique_endpoints_last_window=1, reputation_score=0.0)
    assert trained_scorer.score(attack_feats).score > trained_scorer.score(benign_feats).score


def test_trained_scorer_plugs_into_decision_engine_like_the_heuristic(trained_scorer: TrainedScorer):
    # demonstrates FR-13: swapping the scoring implementation requires no
    # changes to decision.py, only a different ScoreResult producer.
    matches = [RuleMatch("942100-sqli-union-select", "sqli", 5, "query:id")]
    attack_feats = Features(max_field_entropy=4.5, max_field_length=80, rule_hit_count=1,
                             max_rule_severity=5, requests_last_window=1,
                             unique_endpoints_last_window=1, reputation_score=0.0)
    ai_result = trained_scorer.score(attack_feats)
    decision_result = decide(matches, ai_result)
    assert decision_result.decision.value == "block"
    assert decision_result.model_version == "content-classifier-v0.1.0"
