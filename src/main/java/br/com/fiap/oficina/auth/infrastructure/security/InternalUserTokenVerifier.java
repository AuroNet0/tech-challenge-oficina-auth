package br.com.fiap.oficina.auth.infrastructure.security;

import br.com.fiap.oficina.auth.domain.enums.Papel;
import br.com.fiap.oficina.auth.domain.exception.IdentityException;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.json.JsonMapper;
import io.jsonwebtoken.Jwts;
import java.time.Clock;
import java.time.Instant;
import java.util.*;
import static br.com.fiap.oficina.auth.domain.exception.IdentityException.Motivo.*;

public final class InternalUserTokenVerifier {
    private static final JsonMapper JSON = JsonMapper.builder().enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS).build();
    private final KeyProvider keys;
    private final String issuer;
    private final String audience;
    private final Clock clock;

    public InternalUserTokenVerifier(KeyProvider keys, String issuer, String audience, Clock clock) {
        if (issuer == null || !issuer.matches("https://[^\\s?#]{1,240}")
                || audience == null || !audience.matches("[A-Za-z0-9:/_.-]{1,200}")) {
            throw new IllegalArgumentException("Configuracao JWT invalida");
        }
        this.keys = Objects.requireNonNull(keys);
        this.issuer = issuer;
        this.audience = audience;
        this.clock = Objects.requireNonNull(clock);
    }

    public VerifiedUser verificar(String token) {
        try {
            if (token == null || token.length() > 8192 || !token.matches("[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+")) {
                throw new IllegalArgumentException();
            }
            String[] parts = token.split("\\.");
            JsonNode header = JSON.readTree(Base64.getUrlDecoder().decode(parts[0]));
            JsonNode payload = JSON.readTree(Base64.getUrlDecoder().decode(parts[1]));
            if (!header.isObject() || header.size() != 3 || !"RS256".equals(header.path("alg").asText())
                    || !"JWT".equals(header.path("typ").asText()) || !header.path("kid").isTextual()
                    || !header.get("kid").textValue().matches("[A-Za-z0-9_-]{1,80}")) {
                throw new IllegalArgumentException();
            }
            String kid = header.get("kid").textValue();
            var candidates = keys.publicas().stream().filter(key -> key.kid().equals(kid)
                    && key.publicada(clock.instant())).toList();
            if (candidates.size() != 1) { throw new IllegalArgumentException(); }
            Jwts.parser().verifyWith(candidates.getFirst().publica()).requireIssuer(issuer).requireAudience(audience)
                    .clock(() -> Date.from(clock.instant())).sig()
                    .remove(Jwts.SIG.HS256).remove(Jwts.SIG.HS384).remove(Jwts.SIG.HS512)
                    .remove(Jwts.SIG.RS384).remove(Jwts.SIG.RS512)
                    .remove(Jwts.SIG.PS256).remove(Jwts.SIG.PS384).remove(Jwts.SIG.PS512)
                    .remove(Jwts.SIG.ES256).remove(Jwts.SIG.ES384).remove(Jwts.SIG.ES512).remove(Jwts.SIG.EdDSA).and()
                    .build().parseSignedClaims(token);
            if (!payload.isObject() || !payload.path("iss").isTextual() || !issuer.equals(payload.get("iss").textValue())
                    || !payload.path("aud").isArray() || !payload.path("roles").isArray()
                    || !payload.path("sub").isTextual() || !payload.path("jti").isTextual()) {
                throw new IllegalArgumentException();
            }
            boolean expectedAudience = false;
            for (var value : payload.get("aud")) {
                if (!value.isTextual()) { throw new IllegalArgumentException(); }
                expectedAudience |= audience.equals(value.textValue());
            }
            if (!expectedAudience) { throw new IllegalArgumentException(); }
            for (var role : payload.get("roles")) {
                if (!role.isTextual()) { throw new IllegalArgumentException(); }
                Papel.valueOf(role.textValue());
            }
            UUID usuarioId = InternalClientAccessRequest.uuid(payload.get("sub").textValue());
            InternalClientAccessRequest.uuid(payload.get("jti").textValue());
            Instant iat = timestamp(payload, "iat");
            Instant nbf = timestamp(payload, "nbf");
            Instant exp = timestamp(payload, "exp");
            Instant now = clock.instant();
            if (iat.isAfter(now) || !nbf.equals(iat) || !now.isBefore(exp)
                    || !exp.isAfter(iat) || exp.isAfter(iat.plusSeconds(900))) { throw new IllegalArgumentException(); }
            return new VerifiedUser(usuarioId, exp);
        } catch (IdentityException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new IdentityException(CREDENCIAIS_INVALIDAS);
        }
    }

    private Instant timestamp(JsonNode payload, String name) {
        var value = payload.path(name);
        if (!value.isIntegralNumber() || !value.canConvertToLong()) { throw new IllegalArgumentException(); }
        return Instant.ofEpochSecond(value.longValue());
    }

    public record VerifiedUser(UUID usuarioId, Instant expiraEm) {}
}
