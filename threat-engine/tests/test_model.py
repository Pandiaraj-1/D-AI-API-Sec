import subprocess
import sys
from pathlib import Path

import pytest

from app.model import EnsembleThreatModel
from app.features import RequestSignal, extract_features

MODEL_DIR = Path(__file__).resolve().parents[1] / "models"


@pytest.fixture(scope="module", autouse=True)
def trained_model():
    """Train once for the whole test module if artifacts aren't already present."""
    if not (MODEL_DIR / "xgboost_model.joblib").exists():
        repo_root = Path(__file__).resolve().parents[1]
        subprocess.run([sys.executable, "train/train_model.py"], cwd=repo_root, check=True)
    model = EnsembleThreatModel(model_dir=str(MODEL_DIR))
    model.load()
    return model


def test_benign_traffic_is_allowed(trained_model):
    signal = RequestSignal(
        req_rate_10s=0.4, req_rate_60s=2.1, distinct_endpoints_60s=3,
        failed_auth_streak=0, session_age_seconds=2400, geo_velocity_kmph=4.0,
        known_bad_ua_flag=0, response_error_rate_5m=0.01, off_hours_flag=0,
        raw_body='{"item_id": 42, "qty": 1}', param_count=8, baseline_param_count=8,
        numeric_fields={"qty": 1}, baseline_numeric_ranges={"qty": [1, 5]},
    )
    result = trained_model.score(extract_features(signal))
    assert result.decision == "ALLOW"


def test_credential_stuffing_pattern_is_blocked(trained_model):
    signal = RequestSignal(
        req_rate_10s=9.5, req_rate_60s=48.0, distinct_endpoints_60s=1,
        failed_auth_streak=14, session_age_seconds=6, geo_velocity_kmph=900.0,
        known_bad_ua_flag=1, response_error_rate_5m=0.71, off_hours_flag=1,
        raw_body="user=admin&pass=x", param_count=8, baseline_param_count=8,
        numeric_fields={}, baseline_numeric_ranges={},
    )
    result = trained_model.score(extract_features(signal))
    assert result.decision == "BLOCK"


def test_score_is_bounded_between_zero_and_one(trained_model):
    signal = RequestSignal(
        req_rate_10s=0, req_rate_60s=0, distinct_endpoints_60s=0,
        failed_auth_streak=0, session_age_seconds=0, geo_velocity_kmph=0,
        known_bad_ua_flag=0, response_error_rate_5m=0, off_hours_flag=0,
    )
    result = trained_model.score(extract_features(signal))
    assert 0.0 <= result.final_score <= 1.0
    assert 0.0 <= result.isolation_score <= 1.0
    assert 0.0 <= result.xgboost_score <= 1.0
