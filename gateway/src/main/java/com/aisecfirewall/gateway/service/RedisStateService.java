package com.aisecfirewall.gateway.service;

import com.aisecfirewall.gateway.config.SecurityProperties;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Duration;

/**
 * Everything the gateway needs from Redis on the hot path. Every call here
 * targets sub-millisecond latency -- this is the layer that makes
 * "learn asynchronously (Kafka + ML), enforce synchronously (Redis)"
 * actually cheap enough to run on every single request.
 */
@Service
public class RedisStateService {

    private final ReactiveStringRedisTemplate redis;
    private final SecurityProperties properties;

    public RedisStateService(ReactiveStringRedisTemplate redis, SecurityProperties properties) {
        this.redis = redis;
        this.properties = properties;
    }

    /** O(1) lookup: is this client IP currently blocklisted? */
    public Mono<Boolean> isBlocked(String clientIp) {
        return redis.hasKey("blocklist:" + clientIp);
    }

    /** Gateway-side short-circuit: block an offender immediately without waiting on the async pipeline. */
    public Mono<Boolean> blockImmediately(String clientIp, String reason) {
        return redis.opsForValue()
                .set("blocklist:" + clientIp, reason, Duration.ofSeconds(properties.getBlocklistTtlSeconds()));
    }

    /**
     * Fixed-window counter: INCR + EXPIRE-if-new. Cheap approximation of a
     * sliding window; good enough to catch bursty credential-stuffing
     * traffic without the cost of a true sliding-log implementation.
     * Returns the count AFTER incrementing.
     */
    public Mono<Long> incrementWindowCounter(String clientIp, String endpoint, Duration window) {
        String key = "count:" + clientIp + ":" + endpoint;
        return redis.opsForValue().increment(key)
                .flatMap(count -> {
                    if (count == 1L) {
                        return redis.expire(key, window).thenReturn(count);
                    }
                    return Mono.just(count);
                });
    }

    public Mono<Long> incrementFailedAuthStreak(String identityKey) {
        String key = "failstreak:" + identityKey;
        return redis.opsForValue().increment(key)
                .flatMap(count -> redis.expire(key, Duration.ofMinutes(15)).thenReturn(count));
    }

    public Mono<Boolean> resetFailedAuthStreak(String identityKey) {
        return redis.opsForValue().delete("failstreak:" + identityKey);
    }
}
