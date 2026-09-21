package com.aisecfirewall.gateway.filter;

import com.aisecfirewall.gateway.client.ThreatEngineClient;
import com.aisecfirewall.gateway.config.SecurityProperties;
import com.aisecfirewall.gateway.dto.RequestSignalDTO;
import com.aisecfirewall.gateway.dto.ScoreResponseDTO;
import com.aisecfirewall.gateway.service.KafkaRequestPublisher;
import com.aisecfirewall.gateway.service.RedisStateService;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.core.Ordered;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/** Authenticates, scores, audits, and routes every gateway request. */
@Component
public class ZeroTrustFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(ZeroTrustFilter.class);

    private static final Set<String> PUBLIC_PATHS = Set.of(
            "/api/auth/login", "/api/auth/register", "/actuator/health"
    );
    private static final Set<String> KNOWN_AUTOMATION_UA_MARKERS = Set.of(
            "python-requests", "curl/", "scrapy", "headlesschrome", "go-http-client"
    );

    private final JwtAuthValidator jwtAuthValidator;
    private final RedisStateService redisState;
    private final ThreatEngineClient threatEngineClient;
    private final KafkaRequestPublisher kafkaPublisher;
    private final SecurityProperties properties;
    private final ObjectMapper objectMapper;

    public ZeroTrustFilter(JwtAuthValidator jwtAuthValidator,
                            RedisStateService redisState,
                            ThreatEngineClient threatEngineClient,
                            KafkaRequestPublisher kafkaPublisher,
                            SecurityProperties properties,
                            ObjectMapper objectMapper) {
        this.jwtAuthValidator = jwtAuthValidator;
        this.redisState = redisState;
        this.threatEngineClient = threatEngineClient;
        this.kafkaPublisher = kafkaPublisher;
        this.properties = properties;
        this.objectMapper = objectMapper;
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getPath().value();
        String method = request.getMethod().name();
        String clientIp = resolveClientIp(exchange);

        Optional<Claims> claims = PUBLIC_PATHS.contains(path)
                ? Optional.empty()
                : jwtAuthValidator.validate(request.getHeaders().getFirst("Authorization"));

        if (!PUBLIC_PATHS.contains(path) && claims.isEmpty()) {
            return reject(exchange, HttpStatus.UNAUTHORIZED, "Missing or invalid credentials");
        }

        return redisState.isBlocked(clientIp).flatMap(blocked -> {
            if (Boolean.TRUE.equals(blocked)) {
                return reject(exchange, HttpStatus.FORBIDDEN, "Client is temporarily blocked");
            }
            return processBody(exchange, chain, clientIp, method, path, claims);
        });
    }

    private Mono<Void> processBody(ServerWebExchange exchange, GatewayFilterChain chain,
                                    String clientIp, String method, String path,
                                    Optional<Claims> claims) {
        boolean mayHaveBody = Set.of("POST", "PUT", "PATCH").contains(method);
        if (!mayHaveBody) {
            return continuePipeline(exchange, chain, clientIp, method, path, claims, "");
        }

        return DataBufferUtils.join(exchange.getRequest().getBody())
                .defaultIfEmpty(exchange.getResponse().bufferFactory().wrap(new byte[0]))
                .flatMap(dataBuffer -> {
                    byte[] bytes = new byte[dataBuffer.readableByteCount()];
                    dataBuffer.read(bytes);
                    DataBufferUtils.release(dataBuffer);
                    String bodyString = new String(bytes, StandardCharsets.UTF_8);

                    // Re-wrap the request so the buffered body can still be
                    // streamed downstream exactly once we've read it here.
                    ServerHttpRequest decorated = new ServerHttpRequestDecorator(exchange.getRequest()) {
                        @Override
                        public Flux<DataBuffer> getBody() {
                            return Flux.defer(() -> Flux.just(exchange.getResponse().bufferFactory().wrap(bytes)));
                        }
                    };
                    ServerWebExchange mutated = exchange.mutate().request(decorated).build();
                    return continuePipeline(mutated, chain, clientIp, method, path, claims, bodyString);
                });
    }

    private Mono<Void> continuePipeline(ServerWebExchange exchange, GatewayFilterChain chain,
                                         String clientIp, String method, String path,
                                         Optional<Claims> claims, String bodyString) {

        Mono<Long> rate10s = redisState.incrementWindowCounter(clientIp, path, Duration.ofSeconds(10));
        Mono<Long> rate60s = redisState.incrementWindowCounter(clientIp, path, Duration.ofSeconds(60));
        String identityKey = claims.map(Claims::getSubject).orElse(clientIp);
        Mono<Long> failStreak = redisState.incrementFailedAuthStreak(identityKey).defaultIfEmpty(0L);

        return Mono.zip(rate10s, rate60s, failStreak).flatMap(tuple -> {
            RequestSignalDTO signal = buildSignal(
                    tuple.getT1(), tuple.getT2(), tuple.getT3(),
                    exchange, claims, path, bodyString
            );

            kafkaPublisher.publishAsync(clientIp, method, path, signal);

            boolean highRisk = properties.getHighRiskEndpoints().stream().anyMatch(path::startsWith)
                    || tuple.getT1() > properties.getRateEscalationThreshold();

            if (!highRisk) {
                return chain.filter(exchange);
            }

            return threatEngineClient.score(signal).flatMap(result -> {
                if ("BLOCK".equals(result.decision)) {
                    return redisState.blockImmediately(clientIp, result.reason)
                            .then(reject(exchange, HttpStatus.FORBIDDEN, "Request blocked by threat engine: " + result.reason));
                }
                ServerWebExchange tagged = tagRisk(exchange, result);
                return chain.filter(tagged);
            });
        });
    }

    private RequestSignalDTO buildSignal(long rate10s, long rate60s, long failStreak,
                                          ServerWebExchange exchange, Optional<Claims> claims,
                                          String path, String bodyString) {
        RequestSignalDTO signal = new RequestSignalDTO();
        signal.reqRate10s = rate10s;
        signal.reqRate60s = rate60s;
        signal.failedAuthStreak = (int) failStreak;
        signal.distinctEndpoints60s = 1; // refined by the async consumer, which sees the full stream
        signal.sessionAgeSeconds = claims.map(c -> {
            Instant issuedAt = c.getIssuedAt() != null ? c.getIssuedAt().toInstant() : Instant.now();
            return (double) Duration.between(issuedAt, Instant.now()).getSeconds();
        }).orElse(0.0);
        signal.geoVelocityKmph = 0.0; // wire up a GeoIP lookup (e.g. MaxMind) here in production
        signal.knownBadUaFlag = isKnownAutomationUa(exchange) ? 1 : 0;
        signal.responseErrorRate5m = 0.0; // populated by the response-side hook, see RESOURCES in the write-up
        signal.offHoursFlag = isOffHours() ? 1 : 0;
        signal.rawBody = bodyString;
        signal.paramCount = countTopLevelFields(bodyString);
        signal.baselineParamCount = 8;

        Map<String, Double> numericFields = extractNumericFields(bodyString);
        signal.numericFields = numericFields;
        signal.baselineNumericRanges = numericFields.keySet().stream()
                .collect(java.util.stream.Collectors.toMap(
                        f -> f,
                        f -> properties.baselineFor(path, f)
                ));
        return signal;
    }

    private ServerWebExchange tagRisk(ServerWebExchange exchange, ScoreResponseDTO result) {
        exchange.getResponse().getHeaders().add("X-Risk-Level", result.decision);
        exchange.getResponse().getHeaders().add("X-Risk-Score", String.valueOf(result.finalScore));
        return exchange;
    }

    private int countTopLevelFields(String body) {
        if (body == null || body.isBlank()) return 0;
        try {
            Map<?, ?> map = objectMapper.readValue(body, Map.class);
            return map.size();
        } catch (Exception e) {
            return 0;
        }
    }

    private Map<String, Double> extractNumericFields(String body) {
        if (body == null || body.isBlank()) return Map.of();
        try {
            Map<?, ?> map = objectMapper.readValue(body, Map.class);
            return map.entrySet().stream()
                    .filter(e -> e.getValue() instanceof Number)
                    .collect(java.util.stream.Collectors.toMap(
                            e -> String.valueOf(e.getKey()),
                            e -> ((Number) e.getValue()).doubleValue()
                    ));
        } catch (Exception e) {
            return Map.of();
        }
    }

    private boolean isKnownAutomationUa(ServerWebExchange exchange) {
        String ua = exchange.getRequest().getHeaders().getFirst("User-Agent");
        if (ua == null) return true; // no UA at all is itself a signal
        String lower = ua.toLowerCase();
        return KNOWN_AUTOMATION_UA_MARKERS.stream().anyMatch(lower::contains);
    }

    private boolean isOffHours() {
        int hour = java.time.LocalTime.now(java.time.ZoneOffset.UTC).getHour();
        return hour < 6 || hour > 22;
    }

    private String resolveClientIp(ServerWebExchange exchange) {
        String forwarded = exchange.getRequest().getHeaders().getFirst("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return Optional.ofNullable(exchange.getRequest().getRemoteAddress())
                .map(addr -> addr.getAddress().getHostAddress())
                .orElse("unknown");
    }

    private Mono<Void> reject(ServerWebExchange exchange, HttpStatus status, String reason) {
        exchange.getResponse().setStatusCode(status);
        exchange.getResponse().getHeaders().add("Content-Type", "application/json");
        byte[] body = ("{\"error\":\"" + reason + "\"}").getBytes(StandardCharsets.UTF_8);
        DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(body);
        return exchange.getResponse().writeWith(Mono.just(buffer));
    }
}
