from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any

import joblib

from utils.feature_extraction import (
    CANONICAL_FEATURES,
    FEATURE_METADATA,
    LEGITIMATE,
    PHISHING,
    build_feature_table,
    extract_features,
    prepare_model_frame,
)


class PredictionError(ValueError):
    """Raised when a URL cannot be analyzed safely."""


@dataclass
class ModelArtifacts:
    model: Any
    metadata: dict[str, Any]
    model_path: Path
    metadata_path: Path
    feature_names: list[str]


class PredictionService:
    def __init__(self) -> None:
        project_root = Path(__file__).resolve().parent.parent
        self.model_path = project_root / "model" / "phishing_model.pkl"
        self.metadata_path = project_root / "model" / "phishing_model_metadata.json"
        self._artifacts = self._load_artifacts()

    def _load_artifacts(self) -> ModelArtifacts:
        if not self.model_path.exists():
            raise FileNotFoundError(f"Model file not found at {self.model_path}")

        model = joblib.load(self.model_path)
        metadata = json.loads(self.metadata_path.read_text(encoding="utf-8")) if self.metadata_path.exists() else {}
        feature_names = [str(name).lower() for name in metadata.get("feature_names", getattr(model, "feature_names_in_", CANONICAL_FEATURES))]
        return ModelArtifacts(
            model=model,
            metadata=metadata,
            model_path=self.model_path,
            metadata_path=self.metadata_path,
            feature_names=feature_names,
        )

    def dashboard_summary(self) -> dict[str, Any]:
        metrics = self._artifacts.metadata.get("metrics", {})
        dataset = self._artifacts.metadata.get("dataset", {})
        return {
            "model_version": self._artifacts.metadata.get("model_version", "legacy"),
            "evaluation_type": self._artifacts.metadata.get("evaluation_type", "unknown"),
            "dataset_rows": dataset.get("rows"),
            "dataset_columns": dataset.get("columns"),
            "accuracy": metrics.get("accuracy"),
            "precision": metrics.get("precision"),
            "recall": metrics.get("recall"),
            "f1_score": metrics.get("f1_score"),
            "feature_count": len(self._artifacts.feature_names),
        }

    def predict(self, raw_url: str) -> dict[str, Any]:
        try:
            extraction = extract_features(raw_url)
        except ValueError as exc:
            raise PredictionError(str(exc)) from exc

        input_frame = prepare_model_frame(extraction, self._artifacts.feature_names)
        prediction = int(self._artifacts.model.predict(input_frame)[0])
        probabilities = self._artifacts.model.predict_proba(input_frame)[0]
        probability_map = {int(label): float(probability) for label, probability in zip(self._artifacts.model.classes_, probabilities)}

        phishing_probability = probability_map.get(PHISHING, 0.0)
        legitimate_probability = probability_map.get(LEGITIMATE, 0.0)
        confidence = max(phishing_probability, legitimate_probability)
        risk_level = self._risk_level(prediction, phishing_probability, legitimate_probability)
        verdict = "Phishing" if prediction == PHISHING else "Legitimate"

        feature_rows = build_feature_table(extraction).to_dict(orient="records")
        feature_importances = self._artifacts.metadata.get("feature_importances", {})
        suspicious_features, reassuring_features = self._rank_explanations(extraction, feature_importances)

        return {
            "input_url": raw_url,
            "normalized_url": extraction.normalized_url,
            "label": verdict,
            "prediction": prediction,
            "confidence": confidence,
            "confidence_percent": round(confidence * 100, 2),
            "phishing_probability": round(phishing_probability * 100, 2),
            "legitimate_probability": round(legitimate_probability * 100, 2),
            "risk_level": risk_level,
            "risk_tone": "danger" if verdict == "Phishing" else "safe" if risk_level == "Low" else "warning",
            "feature_rows": feature_rows,
            "suspicious_features": suspicious_features,
            "reassuring_features": reassuring_features,
            "suspicious_indicators": extraction.suspicious_indicators,
            "warnings": extraction.warnings,
            "summary_metrics": extraction.display_metrics,
            "lexical_overview": extraction.lexical_overview,
            "scanned_at": "Just now",
        }

    @staticmethod
    def _risk_level(prediction: int, phishing_probability: float, legitimate_probability: float) -> str:
        confidence = max(phishing_probability, legitimate_probability)
        if prediction == PHISHING and confidence >= 0.75:
            return "High"
        if prediction == LEGITIMATE and confidence >= 0.75:
            return "Low"
        return "Medium"

    @staticmethod
    def _rank_explanations(extraction, feature_importances: dict[str, float]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        suspicious: list[dict[str, Any]] = []
        reassuring: list[dict[str, Any]] = []

        for feature_name in CANONICAL_FEATURES:
            value = extraction.features.get(feature_name, 0)
            if value == 0:
                continue
            record = {
                "label": FEATURE_METADATA[feature_name]["label"],
                "description": FEATURE_METADATA[feature_name]["description"],
                "observed": extraction.feature_details.get(feature_name, "No observation available."),
                "importance": round(float(feature_importances.get(feature_name, 0.0)), 4),
            }
            if value == PHISHING:
                suspicious.append(record)
            else:
                reassuring.append(record)

        suspicious.sort(key=lambda item: item["importance"], reverse=True)
        reassuring.sort(key=lambda item: item["importance"], reverse=True)
        return suspicious[:6], reassuring[:6]
