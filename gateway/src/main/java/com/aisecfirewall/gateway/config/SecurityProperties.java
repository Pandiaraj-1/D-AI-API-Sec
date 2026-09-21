package com.aisecfirewall.gateway.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;
import java.util.Map;

/**
 * Binds the "firewall.*" block in application.yml so thresholds can be
 * tuned per-environment (dev/staging/prod) without touching code.
 */
@ConfigurationProperties(prefix = "firewall")
public class SecurityProperties {

    /** Endpoints that always get the synchronous ML score call (login, checkout, password-reset, ...). */
    private List<String> highRiskEndpoints = List.of("/api/auth/login", "/api/checkout/**");

    /** Requests/10s to a single endpoint from a single IP before we escalate to a sync score call. */
    private int rateEscalationThreshold = 15;

    /** Max time we'll wait on the Threat Engine before failing open. */
    private int threatEngineTimeoutMs = 25;

    /** TTL applied when the gateway itself short-circuits a repeat offender. */
    private long blocklistTtlSeconds = 900;

    /**
     * Per-endpoint expected numeric ranges for business-critical fields, keyed
     * as "endpoint:fieldName" -> [min, max], e.g. "/api/checkout:qty": [1, 10].
     * Anything not listed here is treated as unconstrained (no anomaly signal)
     * rather than guessed at -- a false "this field looks weird" is worse than
     * silence for a field nobody has reviewed yet.
     */
    private Map<String, List<Double>> numericBaselines = Map.of();

    public List<String> getHighRiskEndpoints() { return highRiskEndpoints; }
    public void setHighRiskEndpoints(List<String> highRiskEndpoints) { this.highRiskEndpoints = highRiskEndpoints; }
    public int getRateEscalationThreshold() { return rateEscalationThreshold; }
    public void setRateEscalationThreshold(int rateEscalationThreshold) { this.rateEscalationThreshold = rateEscalationThreshold; }
    public int getThreatEngineTimeoutMs() { return threatEngineTimeoutMs; }
    public void setThreatEngineTimeoutMs(int threatEngineTimeoutMs) { this.threatEngineTimeoutMs = threatEngineTimeoutMs; }
    public long getBlocklistTtlSeconds() { return blocklistTtlSeconds; }
    public void setBlocklistTtlSeconds(long blocklistTtlSeconds) { this.blocklistTtlSeconds = blocklistTtlSeconds; }
    public Map<String, List<Double>> getNumericBaselines() { return numericBaselines; }
    public void setNumericBaselines(Map<String, List<Double>> numericBaselines) { this.numericBaselines = numericBaselines; }

    public List<Double> baselineFor(String endpoint, String field) {
        return numericBaselines.getOrDefault(endpoint + ":" + field, List.of(-1.0e9, 1.0e9));
    }
}
