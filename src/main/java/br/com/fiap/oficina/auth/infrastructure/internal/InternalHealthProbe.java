package br.com.fiap.oficina.auth.infrastructure.internal;

import java.net.URI;
import java.net.http.*;
import java.time.Duration;
import java.util.Map;

public final class InternalHealthProbe {
    private InternalHealthProbe() {}

    public static boolean ready(Map<String, String> env) {
        try (var client = HttpClient.newBuilder().sslContext(InternalTls.probeContext(env))
                .connectTimeout(Duration.ofSeconds(3)).build()) {
            var uri = URI.create("https://" + env.getOrDefault("AUTH_INTERNAL_PROBE_HOST", "localhost")
                    + ":" + env.getOrDefault("AUTH_INTERNAL_PORT", "8443") + "/health/ready");
            int status = client.send(HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(5)).GET().build(),
                    HttpResponse.BodyHandlers.discarding()).statusCode();
            if (status != 200) { System.err.println("AUTH_INTERNAL_PROBE_FAILED status=" + status); }
            return status == 200;
        } catch (Exception exception) {
            System.err.println("AUTH_INTERNAL_PROBE_FAILED type=" + exception.getClass().getSimpleName());
            return false;
        }
    }

    public static void main(String[] args) { System.exit(ready(System.getenv()) ? 0 : 1); }
}
