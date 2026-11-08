package br.com.fiap.oficina.auth.infrastructure.security;

import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.*;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.Flow;

public final class TrustedJwksProvider implements KeyProvider, AutoCloseable {
    private static final JsonMapper JSON = JsonMapper.builder().enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS).build();
    private final HttpClient http;
    private final URI uri;
    private final Clock clock;
    private List<SigningKey> keys = List.of();
    private Instant refreshAt = Instant.MIN;

    public TrustedJwksProvider(URI uri, Clock clock) {
        this(uri, clock, HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(1))
                .followRedirects(HttpClient.Redirect.NEVER).build());
    }

    TrustedJwksProvider(URI uri, Clock clock, HttpClient http) {
        if (!"https".equals(uri.getScheme()) || uri.getHost() == null || uri.getUserInfo() != null
                || uri.getQuery() != null || uri.getFragment() != null) {
            throw new IllegalArgumentException("JWKS HTTPS confiavel obrigatorio");
        }
        this.uri = uri;
        this.clock = Objects.requireNonNull(clock);
        this.http = http;
    }

    @Override
    public synchronized List<SigningKey> publicas() {
        if (!clock.instant().isBefore(refreshAt)) { atualizar(); }
        return keys;
    }

    @Override
    public synchronized void atualizar() {
        CompletableFuture<HttpResponse<byte[]>> pending = null;
        try {
            pending = http.sendAsync(HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(2)).GET().build(),
                    ignored -> new LimitedBody());
            var response = pending.get(2, TimeUnit.SECONDS);
            if (response.statusCode() != 200 || !response.headers().firstValue("Content-Type").orElse("")
                    .toLowerCase(Locale.ROOT).matches("application/json(?:;.*)?")) { throw KeyDocuments.indisponivel(); }
            keys = parse(response.body());
            refreshAt = clock.instant().plusSeconds(30);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            refreshAt = Instant.MIN;
            throw KeyDocuments.indisponivel();
        } catch (Exception exception) {
            refreshAt = Instant.MIN;
            throw KeyDocuments.indisponivel();
        } finally {
            if (pending != null && !pending.isDone()) { pending.cancel(true); }
        }
    }

    static List<SigningKey> parse(byte[] body) {
        try {
            if (body.length > 65536) { throw KeyDocuments.indisponivel(); }
            var root = JSON.readTree(body);
            var nodes = root.path("keys");
            if (!nodes.isArray() || nodes.isEmpty() || nodes.size() > 8) { throw KeyDocuments.indisponivel(); }
            var result = new ArrayList<SigningKey>();
            var ids = new HashSet<String>();
            for (var node : nodes) {
                if (!"RSA".equals(node.path("kty").asText()) || !"sig".equals(node.path("use").asText())
                        || !"RS256".equals(node.path("alg").asText()) || node.has("d")
                        || !ids.add(node.path("kid").asText())) { throw KeyDocuments.indisponivel(); }
                var key = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(
                        new BigInteger(1, Base64.getUrlDecoder().decode(node.path("n").asText())),
                        new BigInteger(1, Base64.getUrlDecoder().decode(node.path("e").asText()))));
                result.add(new SigningKey(node.path("kid").asText(), key, null, Instant.EPOCH,
                        Instant.EPOCH.plusSeconds(90), Instant.parse("9999-01-01T00:00:00Z"),
                        Instant.parse("9999-12-31T00:00:00Z")));
            }
            return List.copyOf(result);
        } catch (Exception exception) { throw KeyDocuments.indisponivel(); }
    }

    @Override
    public SigningKey ativa() { throw KeyDocuments.indisponivel(); }

    @Override
    public void close() { http.close(); }

    private static final class LimitedBody implements HttpResponse.BodySubscriber<byte[]> {
        private final CompletableFuture<byte[]> result = new CompletableFuture<>();
        private final ByteArrayOutputStream body = new ByteArrayOutputStream();
        private Flow.Subscription subscription;
        public CompletionStage<byte[]> getBody() { return result; }
        public void onSubscribe(Flow.Subscription value) { subscription = value; value.request(Long.MAX_VALUE); }
        public void onNext(List<ByteBuffer> buffers) {
            for (var buffer : buffers) {
                if (buffer.remaining() > 65536 - body.size()) {
                    subscription.cancel();
                    result.completeExceptionally(KeyDocuments.indisponivel());
                    return;
                }
                byte[] bytes = new byte[buffer.remaining()];
                buffer.get(bytes);
                body.writeBytes(bytes);
            }
        }
        public void onError(Throwable error) { result.completeExceptionally(KeyDocuments.indisponivel()); }
        public void onComplete() { result.complete(body.toByteArray()); }
    }
}
