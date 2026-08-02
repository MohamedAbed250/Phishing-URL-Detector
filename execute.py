from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
from typing import Any

import joblib
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import GridSearchCV, train_test_split

try:
    from imblearn.over_sampling import SMOTE
except Exception:  # pragma: no cover
    SMOTE = None

from Methods import (
    CANONICAL_FEATURES,
    FEATURE_METADATA,
    LEGITIMATE,
    PHISHING,
    build_feature_table,
    extract_features,
    normalize_url,
    prepare_model_frame,
)


LOGGER = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

APP_VERSION = "2.0.0"
MODEL_FILENAME = "phishing_rf_model.pkl"
METADATA_FILENAME = "phishing_rf_model_metadata.json"
DATASET_FILENAME = "Training Dataset.arff"


@dataclass
class ModelArtifacts:
    model: RandomForestClassifier
    metadata: dict[str, Any]
    model_path: Path
    metadata_path: Path
    feature_names: list[str]


def project_dir() -> Path:
    return Path(__file__).resolve().parent


def resolve_path(path_or_name: str | Path | None, default_name: str) -> Path:
    if path_or_name is None:
        return project_dir() / default_name
    path = Path(path_or_name)
    return path if path.is_absolute() else project_dir() / path


def load_arff_dataset(filepath: str | Path) -> pd.DataFrame:
    data_rows = []
    attributes = []
    is_data_section = False
    path = Path(filepath)

    with path.open("r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if not line or line.startswith("%"):
                continue
            lowered = line.lower()
            if lowered.startswith("@attribute"):
                attributes.append(line.split()[1].strip("'\""))
            elif lowered.startswith("@data"):
                is_data_section = True
            elif is_data_section:
                data_rows.append(line.split(","))

    dataset = pd.DataFrame(data_rows, columns=attributes)
    for column in dataset.columns:
        dataset[column] = pd.to_numeric(dataset[column], errors="coerce")
    return dataset


def preprocess_dataset(data: pd.DataFrame) -> pd.DataFrame:
    if data.empty:
        raise ValueError("Dataset is empty.")

    processed = data.copy()
    processed.columns = processed.columns.str.strip().str.lower()
    if "result" not in processed.columns:
        raise ValueError("Dataset must include a 'Result' column.")

    for column in processed.columns:
        processed[column] = pd.to_numeric(processed[column], errors="coerce")

    feature_columns = [column for column in processed.columns if column != "result"]
    for feature_name in CANONICAL_FEATURES:
        if feature_name not in feature_columns:
            raise ValueError(f"Dataset is missing expected feature column '{feature_name}'.")

    processed = processed[CANONICAL_FEATURES + ["result"]]

    for column in CANONICAL_FEATURES:
        if processed[column].isna().any():
            processed[column] = processed[column].fillna(processed[column].median())

    processed["result"] = processed["result"].fillna(processed["result"].mode().iloc[0]).astype(int)
    return processed


def _compute_metrics(y_true: pd.Series, y_pred: pd.Series) -> dict[str, Any]:
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, pos_label=PHISHING, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, pos_label=PHISHING, zero_division=0)),
        "f1_score": float(f1_score(y_true, y_pred, pos_label=PHISHING, zero_division=0)),
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=[PHISHING, LEGITIMATE]).tolist(),
        "labels": [PHISHING, LEGITIMATE],
    }


def _build_metadata(model: RandomForestClassifier, metrics: dict[str, Any], dataset: pd.DataFrame, evaluation_type: str) -> dict[str, Any]:
    feature_importances = {
        feature_name: float(importance)
        for feature_name, importance in zip(CANONICAL_FEATURES, model.feature_importances_)
    }
    return {
        "model_version": APP_VERSION,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "feature_names": CANONICAL_FEATURES,
        "label_mapping": {"phishing": PHISHING, "legitimate": LEGITIMATE},
        "metrics": metrics,
        "evaluation_type": evaluation_type,
        "dataset": {"rows": int(dataset.shape[0]), "columns": int(dataset.shape[1])},
        "feature_importances": feature_importances,
        "sklearn_version": sklearn.__version__,
        "smote_available": SMOTE is not None,
    }


def train_model(
    dataset_path: str | Path | None = None,
    model_path: str | Path | None = None,
    metadata_path: str | Path | None = None,
    random_state: int = 42,
) -> ModelArtifacts:
    dataset_file = resolve_path(dataset_path, DATASET_FILENAME)
    model_file = resolve_path(model_path, MODEL_FILENAME)
    metadata_file = resolve_path(metadata_path, METADATA_FILENAME) if metadata_path is not None else model_file.with_name(METADATA_FILENAME)

    dataset = preprocess_dataset(load_arff_dataset(dataset_file))
    X = dataset[CANONICAL_FEATURES].copy()
    y = dataset["result"].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=random_state
    )

    if SMOTE is not None:
        sampler = SMOTE(random_state=random_state)
        X_train_resampled, y_train_resampled = sampler.fit_resample(X_train, y_train)
    else:
        LOGGER.warning("imblearn is not installed; training will continue without SMOTE.")
        X_train_resampled, y_train_resampled = X_train, y_train

    param_grid = {
        "n_estimators": [200, 300],
        "max_depth": [None, 20],
        "min_samples_leaf": [1, 2],
        "class_weight": ["balanced", "balanced_subsample"],
    }
    grid_search = GridSearchCV(
        estimator=RandomForestClassifier(random_state=random_state, n_jobs=1),
        param_grid=param_grid,
        scoring="f1_macro",
        cv=3,
        n_jobs=1,
        verbose=0,
    )
    grid_search.fit(X_train_resampled, y_train_resampled)

    model = grid_search.best_estimator_
    y_pred = model.predict(X_test)
    metrics = _compute_metrics(y_test, y_pred)
    metadata = _build_metadata(model, metrics, dataset, evaluation_type="holdout_split")

    joblib.dump(model, model_file)
    metadata_file.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    LOGGER.info("Model trained and saved to %s", model_file)
    return ModelArtifacts(model=model, metadata=metadata, model_path=model_file, metadata_path=metadata_file, feature_names=CANONICAL_FEATURES)


def load_model(
    model_path: str | Path | None = None,
    metadata_path: str | Path | None = None,
) -> ModelArtifacts:
    model_file = resolve_path(model_path, MODEL_FILENAME)
    metadata_file = resolve_path(metadata_path, METADATA_FILENAME) if metadata_path is not None else model_file.with_name(METADATA_FILENAME)
    if not model_file.exists():
        raise FileNotFoundError(f"Model file not found: {model_file}")

    model = joblib.load(model_file)
    if metadata_file.exists():
        metadata = json.loads(metadata_file.read_text(encoding="utf-8"))
    else:
        feature_names = [str(name).lower() for name in getattr(model, "feature_names_in_", CANONICAL_FEATURES)]
        metadata = {
            "model_version": "legacy",
            "feature_names": feature_names,
            "label_mapping": {"phishing": PHISHING, "legitimate": LEGITIMATE},
            "metrics": None,
            "evaluation_type": "metadata_unavailable",
            "feature_importances": {
                feature_name: float(importance)
                for feature_name, importance in zip(feature_names, getattr(model, "feature_importances_", [0.0] * len(feature_names)))
            },
            "sklearn_version": sklearn.__version__,
        }

    feature_names = [str(name).lower() for name in metadata.get("feature_names", CANONICAL_FEATURES)]
    return ModelArtifacts(model=model, metadata=metadata, model_path=model_file, metadata_path=metadata_file, feature_names=feature_names)


def get_evaluation_summary(artifacts: ModelArtifacts, dataset_path: str | Path | None = None) -> dict[str, Any]:
    if artifacts.metadata.get("metrics"):
        return artifacts.metadata

    dataset_file = resolve_path(dataset_path, DATASET_FILENAME)
    dataset = preprocess_dataset(load_arff_dataset(dataset_file))
    X = dataset[CANONICAL_FEATURES].copy()
    y = dataset["result"].astype(int)
    y_pred = artifacts.model.predict(X)
    fallback_metrics = _compute_metrics(y, y_pred)
    fallback = dict(artifacts.metadata)
    fallback["metrics"] = fallback_metrics
    fallback["evaluation_type"] = "full_dataset_fallback"
    fallback["dataset"] = {"rows": int(dataset.shape[0]), "columns": int(dataset.shape[1])}
    return fallback


def _risk_level(prediction: int, phishing_probability: float, legitimate_probability: float) -> str:
    confidence = max(phishing_probability, legitimate_probability)
    if prediction == PHISHING and confidence >= 0.75:
        return "High"
    if prediction == LEGITIMATE and confidence >= 0.75:
        return "Low"
    return "Medium"


def _prediction_label(prediction: int) -> str:
    return "Phishing" if prediction == PHISHING else "Legitimate"


def _feature_rationale(extraction, feature_importances: dict[str, float]) -> dict[str, list[dict[str, Any]]]:
    suspicious = []
    reassuring = []

    for feature_name in CANONICAL_FEATURES:
        value = extraction.features.get(feature_name, 0)
        if value == 0:
            continue
        row = {
            "feature": feature_name,
            "label": FEATURE_METADATA[feature_name]["label"],
            "importance": float(feature_importances.get(feature_name, 0.0)),
            "observed": extraction.feature_details.get(feature_name, "No observation available."),
            "description": FEATURE_METADATA[feature_name]["description"],
        }
        if value == PHISHING:
            suspicious.append(row)
        else:
            reassuring.append(row)

    suspicious.sort(key=lambda item: item["importance"], reverse=True)
    reassuring.sort(key=lambda item: item["importance"], reverse=True)
    return {"suspicious": suspicious[:5], "reassuring": reassuring[:5]}


def predict_url(artifacts: ModelArtifacts, raw_url: str) -> dict[str, Any]:
    normalized_url = normalize_url(raw_url)
    extraction = extract_features(normalized_url)
    input_frame = prepare_model_frame(extraction, artifacts.feature_names)

    prediction = int(artifacts.model.predict(input_frame)[0])
    probabilities = artifacts.model.predict_proba(input_frame)[0]
    probability_map = {int(label): float(probability) for label, probability in zip(artifacts.model.classes_, probabilities)}
    phishing_probability = probability_map.get(PHISHING, 0.0)
    legitimate_probability = probability_map.get(LEGITIMATE, 0.0)

    rationale = _feature_rationale(extraction, artifacts.metadata.get("feature_importances", {}))
    confidence = max(phishing_probability, legitimate_probability)

    return {
        "input_url": raw_url,
        "normalized_url": extraction.normalized_url,
        "prediction": prediction,
        "label": _prediction_label(prediction),
        "confidence": confidence,
        "probabilities": {
            "phishing": phishing_probability,
            "legitimate": legitimate_probability,
        },
        "risk_level": _risk_level(prediction, phishing_probability, legitimate_probability),
        "extraction": extraction,
        "feature_table": build_feature_table(extraction),
        "explanations": rationale,
        "suspicious_indicators": extraction.suspicious_indicators,
        "warnings": extraction.warnings,
    }


def predict_batch(artifacts: ModelArtifacts, data: pd.DataFrame, url_column: str | None = None) -> pd.DataFrame:
    if data.empty:
        raise ValueError("The uploaded CSV is empty.")

    selected_column = url_column or _detect_url_column(data)
    results = []

    for raw_value in data[selected_column].fillna("").astype(str):
        try:
            prediction = predict_url(artifacts, raw_value)
            results.append(
                {
                    "url": prediction["normalized_url"],
                    "prediction": prediction["label"],
                    "confidence": round(prediction["confidence"] * 100, 2),
                    "phishing_probability": round(prediction["probabilities"]["phishing"] * 100, 2),
                    "legitimate_probability": round(prediction["probabilities"]["legitimate"] * 100, 2),
                    "risk_level": prediction["risk_level"],
                    "key_features": "; ".join(prediction["suspicious_indicators"][:3]) or "No major suspicious indicators.",
                }
            )
        except Exception as exc:
            results.append(
                {
                    "url": raw_value,
                    "prediction": "Error",
                    "confidence": None,
                    "phishing_probability": None,
                    "legitimate_probability": None,
                    "risk_level": "Unavailable",
                    "key_features": str(exc),
                }
            )

    return pd.DataFrame(results)


def _detect_url_column(data: pd.DataFrame) -> str:
    lowered = {column.lower(): column for column in data.columns}
    for candidate in ["url", "urls", "link", "website"]:
        if candidate in lowered:
            return lowered[candidate]
    return data.columns[0]


def main() -> None:
    parser = argparse.ArgumentParser(description="Phishing URL detector utilities")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("train", help="Train and save the RandomForest model with metadata.")
    predict_parser = subparsers.add_parser("predict", help="Predict a single URL from the command line.")
    predict_parser.add_argument("url", help="URL to classify")

    args = parser.parse_args()

    if args.command == "train":
        artifacts = train_model()
        metrics = artifacts.metadata["metrics"]
        print(json.dumps(metrics, indent=2))
        return

    if args.command == "predict":
        artifacts = load_model()
        result = predict_url(artifacts, args.url)
        print(json.dumps({
            "url": result["normalized_url"],
            "prediction": result["label"],
            "confidence": round(result["confidence"] * 100, 2),
            "risk_level": result["risk_level"],
        }, indent=2))
        return

    parser.print_help()


if __name__ == "__main__":
    main()
