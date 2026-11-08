package br.com.fiap.oficina.auth.infrastructure.internal;

import com.sun.net.httpserver.*;
import java.net.InetSocketAddress;
import java.nio.file.*;
import java.util.Map;

public final class ContainerJwksMain {
    private ContainerJwksMain() {}
    public static void main(String[] args) throws Exception {
        var server = HttpsServer.create(new InetSocketAddress("0.0.0.0", 9443), 8);
        server.setHttpsConfigurator(new HttpsConfigurator(new InternalTls(Map.of(
                "AUTH_INTERNAL_KEYSTORE", "/tls/server.p12", "AUTH_INTERNAL_KEYSTORE_PASSWORD", "ephemeral-test-password",
                "AUTH_INTERNAL_TRUSTSTORE", "/tls/trust.p12", "AUTH_INTERNAL_TRUSTSTORE_PASSWORD", "ephemeral-test-password")).context()));
        server.createContext("/jwks", exchange -> {
            byte[] body = Files.readAllBytes(Path.of("/tls/jwks.json"));
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (var output = exchange.getResponseBody()) { output.write(body); }
            exchange.close();
        });
        server.start();
        System.out.println("JWKS_FIXTURE_READY");
    }
}
