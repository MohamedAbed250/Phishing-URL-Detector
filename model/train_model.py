from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
import sys

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import GridSearchCV

try:
    from imblearn.over_sampling import SMOTE
except Exception:  # pragma: no cover
    SMOTE = None


PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utils.feature_extraction import CANONICAL_FEATURES, LEGITIMATE, PHISHING  # noqa: E402


def compute_metrics(y_true: pd.Series, y_pred: pd.Series) -> dict:
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, pos_label=PHISHING, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, pos_label=PHISHING, zero_division=0)),
        "f1_score": float(f1_score(y_true, y_pred, pos_label=PHISHING, zero_division=0)),
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=[PHISHING, LEGITIMATE]).tolist(),
        "labels": [PHISHING, LEGITIMATE],
    }


def train() -> None:
    train_path = PROJECT_ROOT / "data" / "train.csv"
    test_path = PROJECT_ROOT / "data" / "test.csv"
    model_path = PROJECT_ROOT / "model" / "phishing_model.pkl"
    metadata_path = PROJECT_ROOT / "model" / "phishing_model_metadata.json"

    train_frame = pd.read_csv(train_path)
    test_frame = pd.read_csv(test_path)

    X_train = train_frame[CANONICAL_FEATURES].copy()
    y_train = train_frame["result"].astype(int)
    X_test = test_frame[CANONICAL_FEATURES].copy()
    y_test = test_frame["result"].astype(int)

    if SMOTE is not None:
        sampler = SMOTE(random_state=42)
        X_train, y_train = sampler.fit_resample(X_train, y_train)

    grid_search = GridSearchCV(
        estimator=RandomForestClassifier(random_state=42, n_jobs=1),
        param_grid={
            "n_estimators": [200, 300],
            "max_depth": [None, 20],
            "min_samples_leaf": [1, 2],
            "class_weight": ["balanced", "balanced_subsample"],
        },
        scoring="f1_macro",
        cv=3,
        n_jobs=1,
        verbose=0,
    )
    grid_search.fit(X_train, y_train)

    model = grid_search.best_estimator_
    predictions = model.predict(X_test)
    metrics = compute_metrics(y_test, predictions)

    metadata = {
        "model_version": "flask-1.0.0",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "feature_names": CANONICAL_FEATURES,
        "label_mapping": {"phishing": PHISHING, "legitimate": LEGITIMATE},
        "metrics": metrics,
        "evaluation_type": "holdout_split",
        "dataset": {"rows": int(len(train_frame) + len(test_frame)), "columns": int(train_frame.shape[1])},
        "feature_importances": {
            feature_name: float(importance)
            for feature_name, importance in zip(CANONICAL_FEATURES, model.feature_importances_)
        },
        "smote_available": SMOTE is not None,
    }

    joblib.dump(model, model_path)
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    print(json.dumps(metadata["metrics"], indent=2))


if __name__ == "__main__":
    train()
