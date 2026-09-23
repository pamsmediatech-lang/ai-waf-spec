from ml.dataset import FEATURE_NAMES, build_dataset


def test_dataset_is_reproducible_given_same_seed():
    X1, y1 = build_dataset(n_benign=50, n_malicious=50, seed=7)
    X2, y2 = build_dataset(n_benign=50, n_malicious=50, seed=7)
    assert X1 == X2
    assert y1 == y2


def test_dataset_has_expected_size_and_balance():
    X, y = build_dataset(n_benign=100, n_malicious=100, seed=1)
    assert len(X) == len(y) == 200
    assert y.count(0) == 100
    assert y.count(1) == 100


def test_every_sample_has_all_feature_names_and_no_missing_values():
    X, _y = build_dataset(n_benign=20, n_malicious=20, seed=1)
    for row in X:
        assert set(row.keys()) == set(FEATURE_NAMES)
        for value in row.values():
            assert value is not None


def test_malicious_samples_are_not_all_trivially_flagged_by_rules():
    # regression: an earlier version of the dataset made every malicious
    # sample trigger a rule hit, so the classifier just learned
    # "rule_hit_count > 0" and never had to use behavioral/entropy
    # features. At least some malicious samples (evasive payloads,
    # brute force) must have zero rule hits to make the dataset a real
    # test of the AI layer rather than a rules lookup table.
    X, y = build_dataset(n_benign=300, n_malicious=300, seed=1)
    malicious_with_no_rule_hit = [row for row, label in zip(X, y, strict=True)
                                   if label == 1 and row["rule_hit_count"] == 0]
    assert len(malicious_with_no_rule_hit) > 0
