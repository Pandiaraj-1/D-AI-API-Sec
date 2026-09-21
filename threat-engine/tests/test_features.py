from app.features import RequestSignal, extract_features, FEATURE_ORDER


def _base_signal(**overrides) -> RequestSignal:
    defaults = dict(
        req_rate_10s=0.5, req_rate_60s=1.8, distinct_endpoints_60s=2,
        failed_auth_streak=0, session_age_seconds=1000, geo_velocity_kmph=3.0,
        known_bad_ua_flag=0, response_error_rate_5m=0.02, off_hours_flag=0,
        raw_body="", param_count=0, baseline_param_count=8,
        numeric_fields={}, baseline_numeric_ranges={},
    )
    defaults.update(overrides)
    return RequestSignal(**defaults)


def test_feature_vector_length_matches_feature_order():
    vec = extract_features(_base_signal())
    assert len(vec) == len(FEATURE_ORDER)


def test_empty_body_has_zero_entropy():
    vec = extract_features(_base_signal(raw_body=""))
    entropy = vec[FEATURE_ORDER.index("payload_entropy")]
    assert entropy == 0.0


def test_repeated_character_body_has_low_entropy():
    vec = extract_features(_base_signal(raw_body="aaaaaaaaaaaaaaaa"))
    entropy = vec[FEATURE_ORDER.index("payload_entropy")]
    assert entropy == 0.0  # single repeated symbol carries zero information


def test_param_count_deviation_is_absolute_difference():
    vec = extract_features(_base_signal(param_count=14, baseline_param_count=8))
    dev = vec[FEATURE_ORDER.index("param_count_deviation")]
    assert dev == 6.0


def test_numeric_anomaly_is_zero_within_baseline():
    vec = extract_features(_base_signal(
        numeric_fields={"qty": 2},
        baseline_numeric_ranges={"qty": [1, 5]},
    ))
    anomaly = vec[FEATURE_ORDER.index("price_or_qty_anomaly")]
    assert anomaly == 0.0


def test_numeric_anomaly_is_positive_outside_baseline():
    vec = extract_features(_base_signal(
        numeric_fields={"qty": -15},
        baseline_numeric_ranges={"qty": [1, 3]},
    ))
    anomaly = vec[FEATURE_ORDER.index("price_or_qty_anomaly")]
    assert anomaly > 0.0


def test_numeric_anomaly_clips_at_ten():
    vec = extract_features(_base_signal(
        numeric_fields={"qty": -100000},
        baseline_numeric_ranges={"qty": [1, 3]},
    ))
    anomaly = vec[FEATURE_ORDER.index("price_or_qty_anomaly")]
    assert anomaly == 10.0
