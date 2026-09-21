package com.aisecfirewall.gateway.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Map;

/**
 * Mirrors app.features.RequestSignal (Pydantic model) on the Threat Engine
 * side. The Python service is snake_case on the wire (Pydantic default);
 * Java stays camelCase internally and maps explicitly via @JsonProperty so
 * neither side has to bend its own language conventions.
 */
public class RequestSignalDTO {

    @JsonProperty("req_rate_10s")
    public double reqRate10s;

    @JsonProperty("req_rate_60s")
    public double reqRate60s;

    @JsonProperty("distinct_endpoints_60s")
    public int distinctEndpoints60s;

    @JsonProperty("failed_auth_streak")
    public int failedAuthStreak;

    @JsonProperty("session_age_seconds")
    public double sessionAgeSeconds;

    @JsonProperty("geo_velocity_kmph")
    public double geoVelocityKmph;

    @JsonProperty("known_bad_ua_flag")
    public int knownBadUaFlag;

    @JsonProperty("response_error_rate_5m")
    public double responseErrorRate5m;

    @JsonProperty("off_hours_flag")
    public int offHoursFlag;

    @JsonProperty("raw_body")
    public String rawBody = "";

    @JsonProperty("param_count")
    public int paramCount;

    @JsonProperty("baseline_param_count")
    public int baselineParamCount = 8;

    @JsonProperty("numeric_fields")
    public Map<String, Double> numericFields = Map.of();

    @JsonProperty("baseline_numeric_ranges")
    public Map<String, List<Double>> baselineNumericRanges = Map.of();
}
