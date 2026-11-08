package br.com.fiap.oficina.auth.infrastructure.security;

import br.com.fiap.oficina.auth.domain.exception.IdentityException;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import java.security.KeyFactory;
import java.security.interfaces.*;
import java.security.spec.*;
import java.time.Instant;
import java.util.*;
import static br.com.fiap.oficina.auth.domain.exception.IdentityException.Motivo.PERSISTENCIA;

public final class KeyDocuments {
    private KeyDocuments() {}
    public static IdentityException indisponivel() { return new IdentityException(PERSISTENCIA); }

    static Ring ler(String json) {
        try {
            if (json == null || json.length() > 65536) { throw indisponivel(); }
            var root = JsonMapper.builder().enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION).build().readTree(json);
            String active = root.path("activeKid").asText();
            var nodes = root.path("keys");
            if (!nodes.isArray() || nodes.isEmpty() || nodes.size() > 8) { throw indisponivel(); }
            Map<String, SigningKey> keys = new HashMap<>();
            var factory = KeyFactory.getInstance("RSA");
            for (var node : nodes) {
                String kid = node.path("kid").asText();
                var publicKey = (RSAPublicKey) factory.generatePublic(new X509EncodedKeySpec(
                        Base64.getDecoder().decode(node.path("publicKey").asText())));
                RSAPrivateKey privateKey = null;
                if (node.has("privateKey")) {
                    privateKey = (RSAPrivateKey) factory.generatePrivate(new PKCS8EncodedKeySpec(
                            Base64.getDecoder().decode(node.path("privateKey").asText())));
                }
                var key = new SigningKey(kid, publicKey, privateKey,
                        Instant.parse(node.path("publishFrom").asText()), Instant.parse(node.path("signFrom").asText()),
                        Instant.parse(node.path("signUntil").asText()), Instant.parse(node.path("publishUntil").asText()));
                if (keys.putIfAbsent(kid, key) != null) { throw indisponivel(); }
            }
            if (!keys.containsKey(active)) { throw indisponivel(); }
            return new Ring(active, Map.copyOf(keys));
        } catch (Exception exception) {
            throw indisponivel();
        }
    }

    record Ring(String active, Map<String, SigningKey> keys) {
        @Override
        public String toString() { return "KeyRing[redacted]"; }
    }
}
