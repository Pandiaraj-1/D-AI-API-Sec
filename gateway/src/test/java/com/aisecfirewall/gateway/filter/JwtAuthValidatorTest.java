package com.aisecfirewall.gateway.filter;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JwtAuthValidatorTest {

    private static final String SECRET = "test-secret-key-at-least-32-bytes-long!!";

    @Test
    void validTokenIsAccepted() {
        JwtAuthValidator validator = new JwtAuthValidator(SECRET);
        SecretKey key = Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));
        String token = Jwts.builder()
                .subject("demo_user")
                .issuedAt(new Date())
                .signWith(key)
                .compact();

        Optional<io.jsonwebtoken.Claims> result = validator.validate("Bearer " + token);
        assertTrue(result.isPresent());
        assertEquals("demo_user", result.get().getSubject());
    }

    @Test
    void missingBearerPrefixIsRejected() {
        JwtAuthValidator validator = new JwtAuthValidator(SECRET);
        assertTrue(validator.validate("just-a-raw-token").isEmpty());
    }

    @Test
    void tamperedTokenIsRejected() {
        JwtAuthValidator validator = new JwtAuthValidator(SECRET);
        assertTrue(validator.validate("Bearer not.a.valid.jwt").isEmpty());
    }

    @Test
    void nullTokenIsRejected() {
        JwtAuthValidator validator = new JwtAuthValidator(SECRET);
        assertTrue(validator.validate(null).isEmpty());
    }
}
