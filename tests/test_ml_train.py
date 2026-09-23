from ml.train import MIN_PRECISION, MIN_RECALL, train_and_evaluate


def test_trained_model_meets_quality_gate_on_holdout():
    result = train_and_evaluate(n_benign=300, n_malicious=300, seed=1)
    metrics = result["metadata"]["metrics"]
    assert metrics["recall"] >= MIN_RECALL, metrics
    assert metrics["precision"] >= MIN_PRECISION, metrics


def test_metadata_records_feature_importances_for_explainability():
    result = train_and_evaluate(n_benign=200, n_malicious=200, seed=2)
    importances = result["metadata"]["feature_importances"]
    names = [name for name, _ in importances]
    assert "rule_hit_count" in names
    # importances should sum to ~1.0 (sklearn feature_importances_ property)
    assert abs(sum(v for _, v in importances) - 1.0) < 1e-6


def test_training_is_reproducible_given_same_seed():
    result1 = train_and_evaluate(n_benign=150, n_malicious=150, seed=3)
    result2 = train_and_evaluate(n_benign=150, n_malicious=150, seed=3)
    assert result1["metadata"]["metrics"] == result2["metadata"]["metrics"]
