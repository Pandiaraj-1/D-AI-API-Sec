"""
features.py
Converts raw request telemetry (sent by the Spring Boot gateway) into the
fixed-length numeric feature vector consumed by the ensemble model.

Keeping this in one place means the SAME transformation is used at
training time and at inference time -- a common source of production bugs
in ML systems is "training/serving skew", where the offline feature
pipeline drifts from the online one. Centralizing it here avoids that.
"""
from __future__ import annotations
import math
from collections import Counter
from typing import List
from pydantic import BaseModel, Field


FEATURE_ORDER = [
    "req_rate_10s",
    "req_rate_60s",
    "distinct_endpoints_60s",
    "failed_auth_streak",
    "payload_entropy",
    "param_count_deviation",
    "price_or_qty_anomaly",
    "session_age_seconds",
    "geo_velocity_kmph",
    "known_bad_ua_flag",
    "response_error_rate_5m",
    "off_hours_flag",
]


class RequestSignal(BaseModel):
    """Raw signal payload the gateway forwards for scoring.

    The gateway is responsible for the cheap, stateful counters
    (rates, streaks) since it already owns the Redis connection on the
    hot path. The engine focuses on the parts that need a model:
    payload shape, numeric-field anomalies, and combining everything
    into a single calibrated risk score.
    """

    req_rate_10s: float = Field(..., ge=0)
    req_rate_60s: float = Field(..., ge=0)
    distinct_endpoints_60s: int = Field(..., ge=0)
    failed_auth_streak: int = Field(..., ge=0)
    session_age_seconds: float = Field(..., ge=0)
    geo_velocity_kmph: float = Field(..., ge=0)
    known_bad_ua_flag: int = Field(..., ge=0, le=1)
    response_error_rate_5m: float = Field(..., ge=0, le=1)
    off_hours_flag: int = Field(..., ge=0, le=1)

    # Raw material the engine derives features from server-side:
    raw_body: str = ""
    param_count: int = 0
    baseline_param_count: int = 8
    numeric_fields: dict[str, float] = Field(default_factory=dict)
    baseline_numeric_ranges: dict[str, list[float]] = Field(default_factory=dict)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _numeric_field_anomaly(signal: RequestSignal) -> float:
    """Z-score-like deviation of business-critical numeric fields
    (price, quantity, discount_pct, ...) against a per-field baseline
    range learned from historical legitimate traffic. This is what
    catches business-logic abuse such as a tampered price or a
    negative quantity that a pure network-layer WAF would never see.
    """
    if not signal.numeric_fields:
        return 0.0
    worst = 0.0
    for field, value in signal.numeric_fields.items():
        lo, hi = signal.baseline_numeric_ranges.get(field, [0.0, 1.0])
        span = max(hi - lo, 1e-6)
        if value < lo:
            dev = (lo - value) / span
        elif value > hi:
            dev = (value - hi) / span
        else:
            dev = 0.0
        worst = max(worst, dev)
    return min(worst, 10.0)  # clip so one wild field can't blow up the vector


def extract_features(signal: RequestSignal) -> List[float]:
    """Pure function: RequestSignal -> ordered feature vector (FEATURE_ORDER)."""
    param_dev = abs(signal.param_count - signal.baseline_param_count)
    vector = [
        signal.req_rate_10s,
        signal.req_rate_60s,
        float(signal.distinct_endpoints_60s),
        float(signal.failed_auth_streak),
        _shannon_entropy(signal.raw_body),
        float(param_dev),
        _numeric_field_anomaly(signal),
        signal.session_age_seconds,
        signal.geo_velocity_kmph,
        float(signal.known_bad_ua_flag),
        signal.response_error_rate_5m,
        float(signal.off_hours_flag),
    ]
    assert len(vector) == len(FEATURE_ORDER)
    return vector
