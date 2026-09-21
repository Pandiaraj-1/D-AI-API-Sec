package com.aisecfirewall.gateway.client;

import com.aisecfirewall.gateway.config.SecurityProperties;
import com.aisecfirewall.gateway.dto.RequestSignalDTO;
import com.aisecfirewall.gateway.dto.ScoreResponseDTO;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import io.github.resilience4j.reactor.circuitbreaker.operator.CircuitBreakerOperator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.time.Duration;

/**
 * Calls the FastAPI Threat Engine's synchronous /score endpoint.
 *
 * Two independent safety nets protect the request hot-path:
 *   1. A hard timeout (firewall.threat-engine-timeout-ms, default 25ms) --
 *      the gateway will NOT hold a user's request hostage waiting on a
 *      model call.
 *   2. A circuit breaker -- if the Threat Engine is unhealthy or slow
 *      across many requests, stop calling it altogether for a cool-down
 *      window instead of paying the timeout cost on every request.
 *
 * On ANY failure (timeout, circuit open, 5xx) we FAIL OPEN: allow the
 * request through, but mark it as unscored so it is still audited. This
 * is a deliberate availability-over-precision trade-off appropriate for
 * a gateway sitting in front of production traffic -- see the "Design
 * Decisions" section of the write-up for the reasoning and the
 * alternative (fail-closed) for endpoints where that trade-off should
 * flip, e.g. wire transfers.
 */
@Component
public class ThreatEngineClient {

    private static final Logger log = LoggerFactory.getLogger(ThreatEngineClient.class);
    private static final ScoreResponseDTO UNSCORED = fallback();

    private final WebClient webClient;
    private final CircuitBreaker circuitBreaker;
    private final SecurityProperties properties;

    public ThreatEngineClient(WebClient threatEngineWebClient,
                               CircuitBreakerRegistry registry,
                               SecurityProperties properties) {
        this.webClient = threatEngineWebClient;
        this.circuitBreaker = registry.circuitBreaker("threatEngine");
        this.properties = properties;
    }

    public Mono<ScoreResponseDTO> score(RequestSignalDTO signal) {
        return webClient.post()
                .uri("/score")
                .bodyValue(signal)
                .retrieve()
                .bodyToMono(ScoreResponseDTO.class)
                .timeout(Duration.ofMillis(properties.getThreatEngineTimeoutMs()))
                .transformDeferred(CircuitBreakerOperator.of(circuitBreaker))
                .onErrorResume(ex -> {
                    log.warn("Threat Engine unavailable, failing open: {}", ex.toString());
                    return Mono.just(UNSCORED);
                });
    }

    private static ScoreResponseDTO fallback() {
        ScoreResponseDTO dto = new ScoreResponseDTO();
        dto.isolationScore = -1;
        dto.xgboostScore = -1;
        dto.finalScore = -1;
        dto.decision = "UNSCORED";
        dto.reason = "Threat engine timeout/circuit-open - allowed with async follow-up";
        return dto;
    }
}
