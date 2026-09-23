"""Trening + walidacja Content Classifier (spec SPEC.md §7.1, §10.1, §12.2).

Uruchomienie:
    .venv/Scripts/python -m ml.train

Zapisuje:
    ml/artifacts/content_classifier_<version>.joblib  -- model
    ml/artifacts/content_classifier_<version>.json    -- metadane
        (spec §10.1: wersja, metryki, data treningu) + feature importances
        użyte jako globalne top_features do explainability (§7.4).

ponytail: metryki liczone na losowym hold-out (nie podziale czasowym z
§12.2 -- dane są syntetyczne, nie mają realnej osi czasu). Do zamiany
na podział czasowy, gdy wejdą prawdziwe dane produkcyjne.
"""
from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, precision_recall_fscore_support
from sklearn.model_selection import train_test_split

from ml.dataset import FEATURE_NAMES, build_dataset

MODEL_VERSION = "content-classifier-v0.1.0"
ARTIFACTS_DIR = Path(__file__).parent / "artifacts"

# Bramka jakości zgodna z duchem NFR-5 (recall >= 95% w docelowym
# systemie); na syntetycznym zbiorze próg jest ostrzejszy, bo klasy są
# łatwiej separowalne niż prawdziwy ruch -- to sanity check pipeline'u,
# nie dowód gotowości produkcyjnej (patrz spec §10.2: shadow mode przed
# jakimkolwiek wpływem na ruch).
MIN_RECALL = 0.95
MIN_PRECISION = 0.90


def train_and_evaluate(n_benign: int = 600, n_malicious: int = 600, seed: int = 42) -> dict:
    X_dicts, y = build_dataset(n_benign=n_benign, n_malicious=n_malicious, seed=seed)
    X = [[row[name] for name in FEATURE_NAMES] for row in X_dicts]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=seed, stratify=y
    )

    model = RandomForestClassifier(n_estimators=200, max_depth=6, random_state=seed)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_test, y_pred, average="binary", pos_label=1
    )
    report_text = classification_report(y_test, y_pred, target_names=["benign", "malicious"])

    feature_importances = sorted(
        zip(FEATURE_NAMES, model.feature_importances_.tolist(), strict=True),
        key=lambda pair: pair[1], reverse=True,
    )

    metadata = {
        "model_version": MODEL_VERSION,
        "trained_at": datetime.now(UTC).isoformat(),
        "feature_names": FEATURE_NAMES,
        "dataset": {"n_benign": n_benign, "n_malicious": n_malicious, "seed": seed},
        "metrics": {"precision": precision, "recall": recall, "f1": f1},
        "feature_importances": feature_importances,
        "report_text": report_text,
    }
    return {"model": model, "metadata": metadata}


def save_artifacts(model, metadata: dict, artifacts_dir: Path = ARTIFACTS_DIR) -> tuple[Path, Path]:
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    model_path = artifacts_dir / f"{metadata['model_version']}.joblib"
    meta_path = artifacts_dir / f"{metadata['model_version']}.json"
    joblib.dump(model, model_path)
    meta_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return model_path, meta_path


def main() -> int:
    result = train_and_evaluate()
    metadata = result["metadata"]
    print(metadata["report_text"])
    print(f"precision={metadata['metrics']['precision']:.4f} "
          f"recall={metadata['metrics']['recall']:.4f} "
          f"f1={metadata['metrics']['f1']:.4f}")
    print("top features:", metadata["feature_importances"][:3])

    model_path, meta_path = save_artifacts(result["model"], metadata)
    print(f"saved model -> {model_path}")
    print(f"saved metadata -> {meta_path}")

    if metadata["metrics"]["recall"] < MIN_RECALL or metadata["metrics"]["precision"] < MIN_PRECISION:
        print(f"QUALITY GATE FAILED: recall/precision below threshold "
              f"(min recall={MIN_RECALL}, min precision={MIN_PRECISION})", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
