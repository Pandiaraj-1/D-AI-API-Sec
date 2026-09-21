"""
train_model.py
Generates a synthetic, labeled traffic dataset and trains the two models
that make up the ensemble.

This is a SYNTHETIC DATA GENERATOR for a portfolio project -- it produces
statistical distributions that resemble the three traffic classes below,
not real captured traffic. That is intentional: it lets anyone clone the
repo and get a working, reproducible model without needing a real
production dataset (which would also raise privacy concerns). In a real
company you would replace `generate_dataset()` with a query against your
own historical, labeled traffic warehouse and keep everything else the
same -- that swap is the whole point of isolating this step.

Run:
    python train/train_model.py
Outputs:
    models/isolation_forest.joblib
    models/xgboost_model.joblib
    models/metadata.json
"""
from __future__ import annotations
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score
from xgboost import XGBClassifier
import joblib

sys.path.append(str(Path(__file__).resolve().parents[1]))
from app.features import FEATURE_ORDER  # noqa: E402

RNG = np.random.default_rng(42)
MODEL_DIR = Path(__file__).resolve().parents[1] / "models"


def _benign(n: int) -> pd.DataFrame:
    return pd.DataFrame({
        "req_rate_10s": RNG.gamma(1.2, 0.4, n),
        "req_rate_60s": RNG.gamma(2.0, 1.5, n),
        "distinct_endpoints_60s": RNG.poisson(3, n),
        "failed_auth_streak": RNG.poisson(0.05, n),
        "payload_entropy": RNG.normal(3.4, 0.4, n).clip(0, 8),
        "param_count_deviation": RNG.poisson(0.3, n),
        "price_or_qty_anomaly": np.abs(RNG.normal(0, 0.15, n)),
        "session_age_seconds": RNG.exponential(1800, n),
        "geo_velocity_kmph": np.abs(RNG.normal(5, 15, n)),
        "known_bad_ua_flag": RNG.binomial(1, 0.01, n),
        "response_error_rate_5m": np.abs(RNG.normal(0.02, 0.03, n)).clip(0, 1),
        "off_hours_flag": RNG.binomial(1, 0.12, n),
        "label": 0,
    })


def _credential_stuffing(n: int) -> pd.DataFrame:
    return pd.DataFrame({
        "req_rate_10s": RNG.gamma(6.0, 1.2, n) + 3,
        "req_rate_60s": RNG.gamma(8.0, 3.0, n) + 10,
        "distinct_endpoints_60s": RNG.poisson(1.1, n),  # hammering one endpoint
        "failed_auth_streak": RNG.poisson(9, n) + 2,
        "payload_entropy": RNG.normal(4.2, 0.6, n).clip(0, 8),
        "param_count_deviation": RNG.poisson(0.4, n),
        "price_or_qty_anomaly": np.abs(RNG.normal(0, 0.2, n)),
        "session_age_seconds": RNG.exponential(15, n),  # brand-new sessions
        "geo_velocity_kmph": np.abs(RNG.normal(650, 500, n)),  # proxy rotation
        "known_bad_ua_flag": RNG.binomial(1, 0.55, n),
        "response_error_rate_5m": np.abs(RNG.normal(0.6, 0.2, n)).clip(0, 1),
        "off_hours_flag": RNG.binomial(1, 0.4, n),
        "label": 1,
    })


def _business_logic_abuse(n: int) -> pd.DataFrame:
    return pd.DataFrame({
        "req_rate_10s": RNG.gamma(1.3, 0.5, n),  # looks like ONE normal user
        "req_rate_60s": RNG.gamma(2.2, 1.6, n),
        "distinct_endpoints_60s": RNG.poisson(2.5, n),
        "failed_auth_streak": RNG.poisson(0.05, n),
        "payload_entropy": RNG.normal(3.6, 0.5, n).clip(0, 8),
        "param_count_deviation": RNG.poisson(4.5, n) + 1,  # extra hidden fields
        "price_or_qty_anomaly": np.abs(RNG.normal(4.5, 2.0, n)) + 1.5,  # tampered price/qty
        "session_age_seconds": RNG.exponential(2200, n),
        "geo_velocity_kmph": np.abs(RNG.normal(6, 12, n)),
        "known_bad_ua_flag": RNG.binomial(1, 0.03, n),
        "response_error_rate_5m": np.abs(RNG.normal(0.05, 0.05, n)).clip(0, 1),
        "off_hours_flag": RNG.binomial(1, 0.2, n),
        "label": 1,
    })


def generate_dataset(n_benign=6000, n_stuffing=900, n_abuse=600) -> pd.DataFrame:
    df = pd.concat([
        _benign(n_benign),
        _credential_stuffing(n_stuffing),
        _business_logic_abuse(n_abuse),
    ], ignore_index=True)
    return df.sample(frac=1.0, random_state=42).reset_index(drop=True)


def main():
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    df = generate_dataset()
    X = df[FEATURE_ORDER].values
    y = df["label"].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    # --- IsolationForest: fit on BENIGN ONLY (unsupervised) ---
    benign_mask = y_train == 0
    iso = IsolationForest(
        n_estimators=200,
        contamination=0.05,
        random_state=42,
        n_jobs=-1,
    )
    iso.fit(X_train[benign_mask])
    iso_scores_train = iso.decision_function(X_train)

    # --- XGBoost: fit on the full labeled set (supervised) ---
    pos_weight = (y_train == 0).sum() / max((y_train == 1).sum(), 1)
    xgb = XGBClassifier(
        n_estimators=300,
        max_depth=5,
        learning_rate=0.08,
        subsample=0.9,
        colsample_bytree=0.9,
        eval_metric="logloss",
        scale_pos_weight=pos_weight,
        random_state=42,
    )
    xgb.fit(X_train, y_train)

    # --- Evaluate on held-out test set ---
    y_pred = xgb.predict(X_test)
    y_proba = xgb.predict_proba(X_test)[:, 1]
    print("=== XGBoost classification report (test set) ===")
    print(classification_report(y_test, y_pred, target_names=["benign", "malicious"]))
    print(f"ROC-AUC: {roc_auc_score(y_test, y_proba):.4f}")

    # --- Persist artifacts ---
    joblib.dump(iso, MODEL_DIR / "isolation_forest.joblib")
    joblib.dump(xgb, MODEL_DIR / "xgboost_model.joblib")
    metadata = {
        "feature_order": FEATURE_ORDER,
        "iso_score_min": float(iso_scores_train.min()),
        "iso_score_max": float(iso_scores_train.max()),
        "trained_rows": int(len(df)),
    }
    (MODEL_DIR / "metadata.json").write_text(json.dumps(metadata, indent=2))
    print(f"\nSaved model artifacts to {MODEL_DIR}/")


if __name__ == "__main__":
    main()
