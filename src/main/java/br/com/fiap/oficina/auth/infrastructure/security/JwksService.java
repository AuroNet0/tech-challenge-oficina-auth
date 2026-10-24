package br.com.fiap.oficina.auth.infrastructure.security;

import java.math.BigInteger;
import java.util.*;

public final class JwksService {
    private final KeyProvider provider;
    public JwksService(KeyProvider provider) { this.provider = provider; }

    public Map<String, Object> documento() {
        var keys = provider.publicas().stream().map(key -> Map.of(
                "kty", "RSA", "kid", key.kid(), "use", "sig", "alg", "RS256",
                "n", encode(key.publica().getModulus()), "e", encode(key.publica().getPublicExponent()))).toList();
        if (keys.isEmpty()) { throw KeyDocuments.indisponivel(); }
        return Map.of("keys", keys);
    }

    private String encode(BigInteger number) {
        byte[] bytes = number.toByteArray();
        if (bytes[0] == 0) { bytes = Arrays.copyOfRange(bytes, 1, bytes.length); }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
