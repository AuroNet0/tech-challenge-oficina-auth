package br.com.fiap.oficina.auth.infrastructure.security;

import br.com.fiap.oficina.auth.domain.exception.IdentityException;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import java.nio.ByteBuffer;
import java.nio.charset.*;
import java.time.Clock;
import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import static br.com.fiap.oficina.auth.domain.exception.IdentityException.Motivo.*;

public final class InternalClientAccessRequest {
    private static final JsonMapper JSON = JsonMapper.builder().enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS).build();
    private final UUID clienteId;
    private final String token;
    private final UUID requestId;
    private final Instant issuedAt;

    private InternalClientAccessRequest(UUID clienteId, String token, UUID requestId, Instant issuedAt) {
        this.clienteId = clienteId;
        this.token = token;
        this.requestId = requestId;
        this.issuedAt = issuedAt;
    }

    public static InternalClientAccessRequest parse(byte[] body) {
        try {
            if (body == null || body.length > 12288) { throw new IllegalArgumentException(); }
            String text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(body)).toString();
            var root = JSON.readTree(text);
            Set<String> fields = Set.of("clienteId", "userAccessToken", "requestId", "issuedAt");
            if (root == null || !root.isObject() || root.size() != fields.size()) { throw new IllegalArgumentException(); }
            for (String field : fields) {
                if (!root.path(field).isTextual()) { throw new IllegalArgumentException(); }
            }
            String token = root.get("userAccessToken").textValue();
            if (token.isEmpty() || token.length() > 8192) { throw new IllegalArgumentException(); }
            return new InternalClientAccessRequest(uuid(root.get("clienteId").textValue()), token,
                    uuid(root.get("requestId").textValue()), Instant.parse(root.get("issuedAt").textValue()));
        } catch (Exception exception) {
            throw new IdentityException(INVALIDO);
        }
    }

    static UUID uuid(String value) {
        UUID result = UUID.fromString(value);
        if (!result.toString().equals(value)) { throw new IllegalArgumentException(); }
        return result;
    }

    public void exigirAtual(Clock clock) {
        Instant now = clock.instant();
        if (issuedAt.isAfter(now.plusSeconds(5)) || !now.isBefore(issuedAt.plusSeconds(60))) {
            throw new IdentityException(CREDENCIAIS_INVALIDAS);
        }
    }

    public UUID clienteId() { return clienteId; }
    public String userAccessToken() { return token; }
    public UUID requestId() { return requestId; }
    public Instant issuedAt() { return issuedAt; }

    @Override
    public String toString() { return "InternalClientAccessRequest[redacted]"; }
}
