package br.com.fiap.oficina.auth.service;

import br.com.fiap.oficina.auth.model.ClienteAuth;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class JwtServiceTest {

    private static final String JWT_SECRET = "12345678901234567890123456789012";
    private static final Instant NOW = Instant.parse("2026-09-07T12:00:00Z");
    private static final Clock FIXED_CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);

    @Test
    void shouldGenerateTokenForValidCliente() {
        ClienteAuth cliente = new ClienteAuth(10L, "Maria Silva", "123.456.789-09", true);
        JwtService jwtService = new JwtService(JWT_SECRET, FIXED_CLOCK);

        String token = jwtService.generateToken(cliente);

        assertNotNull(token);
        assertFalse(token.isBlank());

        Claims claims = parseClaims(token);
        assertEquals("12345678909", claims.getSubject());
        assertEquals(10L, ((Number) claims.get("clienteId")).longValue());
        assertEquals("Maria Silva", claims.get("nome"));
        assertEquals("CLIENTE", claims.get("tipo"));
        assertEquals(Date.from(NOW), claims.getIssuedAt());
        assertEquals(Date.from(NOW.plus(1, ChronoUnit.HOURS)), claims.getExpiration());
    }

    @Test
    void shouldFailWhenJwtSecretIsNotConfigured() {
        ClienteAuth cliente = new ClienteAuth(10L, "Maria Silva", "12345678909", true);
        JwtService jwtService = new JwtService("", FIXED_CLOCK);

        assertThrows(ConfigurationException.class, () -> jwtService.generateToken(cliente));
    }

    private Claims parseClaims(String token) {
        return Jwts.parser()
                .clock(() -> Date.from(NOW))
                .verifyWith(buildApiCompatibleSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private javax.crypto.SecretKey buildApiCompatibleSigningKey() {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashedSecret = digest.digest(JWT_SECRET.getBytes(StandardCharsets.UTF_8));
            return Keys.hmacShaKeyFor(hashedSecret);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException(exception);
        }
    }
}
