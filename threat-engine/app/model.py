"""
model.py
The ensemble threat-scoring model.

Design rationale (worth understanding, not just running):
  - IsolationForest is unsupervised. It is trained ONLY on benign traffic
    and learns what "normal" looks like. It generalizes to attack
    patterns nobody has labeled yet -- the zero-day case.
  - XGBoost is supervised. It is trained on a labeled mix of benign and
    attack traffic and is much sharper at recognizing patterns that
    resemble known attacks (credential stuffing, business-logic abuse)
    because it has seen negative examples, not just "different" examples.
  - Combining them is a standard technique in production fraud/security
    systems: the unsupervised model is a safety net for novel behavior,
    the supervised model is a precision instrument for known behavior.

The final score is a calibrated 0..1 "risk" value, not a raw model
output, because thresholds and dashboards need a stable, comparable
scale even if the underlying models are retrained.
"""
from __future__ import annotations
import json
from dataclasses import dataclass
from pathlib import Path
from typing import List

import joblib
import numpy as np


@dataclass
class ScoreResult:
    isolation_score: float   # normalized 0..1, higher = more anomalous
    xgboost_score: float     # probability of the "malicious" class, 0..1
    final_score: float       # weighted ensemble, 0..1
    decision: str            # ALLOW | CHALLENGE | BLOCK
    reason: str


class EnsembleThreatModel:
    ISO_WEIGHT = 0.35
    XGB_WEIGHT = 0.65
    BLOCK_THRESHOLD = 0.85
    CHALLENGE_THRESHOLD = 0.60

    def __init__(self, model_dir: str = "models"):
        self.model_dir = Path(model_dir)
        self.isolation_forest = None
        self.xgb_model = None
        self.iso_score_min = -0.5
        self.iso_score_max = 0.5

    def load(self) -> None:
        self.isolation_forest = joblib.load(self.model_dir / "isolation_forest.joblib")
        self.xgb_model = joblib.load(self.model_dir / "xgboost_model.joblib")
        meta = json.loads((self.model_dir / "metadata.json").read_text())
        self.iso_score_min = meta["iso_score_min"]
        self.iso_score_max = meta["iso_score_max"]

    def _normalize_iso(self, raw_score: float) -> float:
        # decision_function: LOWER (more negative) = more anomalous.
        # Flip and min-max scale using ranges captured at training time.
        span = max(self.iso_score_max - self.iso_score_min, 1e-6)
        anomaly = (self.iso_score_max - raw_score) / span
        return float(np.clip(anomaly, 0.0, 1.0))

    def score(self, feature_vector: List[float]) -> ScoreResult:
        x = np.asarray(feature_vector, dtype=float).reshape(1, -1)

        raw_iso = float(self.isolation_forest.decision_function(x)[0])
        iso_norm = self._normalize_iso(raw_iso)

        xgb_prob = float(self.xgb_model.predict_proba(x)[0][1])

        final = self.ISO_WEIGHT * iso_norm + self.XGB_WEIGHT * xgb_prob

        if final >= self.BLOCK_THRESHOLD:
            decision, reason = "BLOCK", "High combined anomaly + attack-pattern probability"
        elif final >= self.CHALLENGE_THRESHOLD:
            decision, reason = "CHALLENGE", "Elevated risk -- require step-up auth (OTP/CAPTCHA)"
        else:
            decision, reason = "ALLOW", "Risk within normal operating range"

        return ScoreResult(
            isolation_score=round(iso_norm, 4),
            xgboost_score=round(xgb_prob, 4),
            final_score=round(final, 4),
            decision=decision,
            reason=reason,
        )
