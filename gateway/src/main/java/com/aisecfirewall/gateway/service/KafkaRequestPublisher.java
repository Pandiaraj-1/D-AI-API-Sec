package com.aisecfirewall.gateway.service;

import com.aisecfirewall.gateway.dto.RequestSignalDTO;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/**
 * Publishes request telemetry to Kafka for the async scoring / audit path.
 * This NEVER blocks the reactive request chain -- KafkaTemplate.send()
 * returns immediately and we just log failures. Losing an occasional
 * audit event is an acceptable trade-off for never adding latency to a
 * real user's request because of a Kafka hiccup.
 */
@Service
public class KafkaRequestPublisher {

    private static final Logger log = LoggerFactory.getLogger(KafkaRequestPublisher.class);
    private static final String RAW_TOPIC = "api.requests.raw";

    private final KafkaTemplate<String, String> kafkaTemplate;
    private final ObjectMapper objectMapper;

    public KafkaRequestPublisher(KafkaTemplate<String, String> kafkaTemplate, ObjectMapper objectMapper) {
        this.kafkaTemplate = kafkaTemplate;
        this.objectMapper = objectMapper;
    }

    public void publishAsync(String clientIp, String method, String endpoint, RequestSignalDTO signal) {
        try {
            String requestId = UUID.randomUUID().toString();
            Map<String, Object> envelope = Map.of(
                    "request_id", requestId,
                    "client_ip", clientIp,
                    "method", method,
                    "endpoint", endpoint,
                    "timestamp", Instant.now().toString(),
                    "signal", signal
            );
            String json = objectMapper.writeValueAsString(envelope);
            kafkaTemplate.send(RAW_TOPIC, clientIp, json)
                    .whenComplete((result, ex) -> {
                        if (ex != null) {
                            log.warn("Failed to publish request telemetry to Kafka: {}", ex.toString());
                        }
                    });
        } catch (Exception e) {
            log.warn("Failed to serialize request telemetry, dropping: {}", e.toString());
        }
    }
}
