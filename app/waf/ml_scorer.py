"""Warstwa 3, wariant "prawdziwy model" (spec §7.1) -- alternatywa dla
heurystyki w scoring.py, ten sam kontrakt (Features -> ScoreResult),
zgodnie z FR-13 (podmiana modelu bez zmian w decision.py).

ponytail: top_features to globalne feature_importances_ modelu (te same
dla każdej predykcji), nie per-instancyjne wyjaśnienie (SHAP) -- SHAP to
dodatkowa zależność nieuzasadniona na obecnym etapie (brak jeszcze
prawdziwych danych produkcyjnych do treningu, patrz ml/dataset.py).
Wystarcza do audytu "dlaczego model w ogóle tak waży cechy" (§7.4),
nie do wyjaśnienia pojedynczej decyzji cecha-po-cesze.

Fail-open (spec §13.1): jeśli artefakt modelu jest niedostępny/uszkodzony,
`load_scorer` rzuca `ModelUnavailable` zamiast cichego fallbacku -- to
proxy.py/pipeline decyduje, czy przy braku modelu polegać wyłącznie na
regułach (fail-open na warstwie AI) czy zablokować start (decyzja
operacyjna, nie coś, co scorer ma ukrywać).
"""
from __future__ import annotations

import json
from dataclasses import fields
from pathlib import Path

import joblib

from .features import Features
from .scoring import ScoreResult

FEATURE_NAMES: list[str] = [f.name for f in fields(Features)]
DEFAULT_ARTIFACTS_DIR = Path(__file__).parent.parent.parent / "ml" / "artifacts"


class ModelUnavailable(RuntimeError):
    pass


class TrainedScorer:
    def __init__(self, model, model_version: str, feature_importances: list[tuple[str, float]]):
        self._model = model
        self._model_version = model_version
        self._top_features_global = [name for name, _ in feature_importances[:3]]

    @classmethod
    def load(cls, model_version: str, artifacts_dir: Path = DEFAULT_ARTIFACTS_DIR) -> TrainedScorer:
        model_path = artifacts_dir / f"{model_version}.joblib"
        meta_path = artifacts_dir / f"{model_version}.json"
        if not model_path.exists() or not meta_path.exists():
            raise ModelUnavailable(f"missing artifact for model_version={model_version!r} in {artifacts_dir}")
        try:
            model = joblib.load(model_path)
            metadata = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception as exc:  # artefakt uszkodzony/niekompatybilna wersja sklearn itp.
            raise ModelUnavailable(f"failed to load model_version={model_version!r}: {exc}") from exc
        return cls(model, model_version, [tuple(pair) for pair in metadata["feature_importances"]])

    def score(self, features: Features) -> ScoreResult:
        vector = [[getattr(features, name) for name in FEATURE_NAMES]]
        malicious_probability = float(self._model.predict_proba(vector)[0][1])
        return ScoreResult(
            score=round(malicious_probability, 4),
            top_features=self._top_features_global,
            model_version=self._model_version,
        )
