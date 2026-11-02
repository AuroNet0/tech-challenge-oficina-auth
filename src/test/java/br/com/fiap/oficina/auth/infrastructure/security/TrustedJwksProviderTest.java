package br.com.fiap.oficina.auth.infrastructure.security;

import br.com.fiap.oficina.auth.infrastructure.internal.InternalTls;
import br.com.fiap.oficina.auth.support.TestTls;
import br.com.fiap.oficina.auth.support.AuthFixtures.MutableClock;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.net.*;
import java.net.http.HttpClient;
import java.nio.file.Path;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.atomic.*;
import static br.com.fiap.oficina.auth.support.AuthFixtures.*;
import static org.junit.jupiter.api.Assertions.*;

class TrustedJwksProviderTest {
    @TempDir static Path directory;
    static TestTls tls;
    final MutableClock clock = new MutableClock(NOW);
    final AtomicInteger calls = new AtomicInteger();
    final AtomicInteger status = new AtomicInteger(200);
    final AtomicReference<String> document = new AtomicReference<>();
    HttpsServer server;
    TrustedJwksProvider provider;

    @BeforeAll static void certificates() throws Exception { tls = new TestTls(directory); }

    @BeforeEach void start() throws Exception {
        document.set(new ObjectMapper().writeValueAsString(new JwksService(provider(clock)).documento()));
        server = HttpsServer.create(new InetSocketAddress("localhost", 0), 8);
        server.setHttpsConfigurator(new HttpsConfigurator(new InternalTls(tls.environment()).context()));
        server.createContext("/jwks", exchange -> {
            calls.incrementAndGet();
            byte[] bytes = document.get().getBytes(java.nio.charset.StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(status.get(), bytes.length);
            try (var output = exchange.getResponseBody()) { output.write(bytes); }
            exchange.close();
        });
        server.start();
        provider = new TrustedJwksProvider(URI.create("https://localhost:" + server.getAddress().getPort() + "/jwks"), clock,
                HttpClient.newBuilder().sslContext(tls.context(null)).connectTimeout(Duration.ofSeconds(1)).build());
    }

    @AfterEach void stop() { provider.close(); server.stop(0); }

    @Test void validaJwtDoMesmoEmissorComSomenteChavesPublicas() {
        var id = UUID.randomUUID();
        String token = new Rs256TokenIssuer(provider(clock), clock, ISSUER, AUDIENCE, 60)
                .emitir(id, Set.of(br.com.fiap.oficina.auth.domain.enums.Papel.CLIENTE)).accessToken();
        assertEquals(id, new InternalUserTokenVerifier(provider, ISSUER, AUDIENCE, clock).verificar(token).usuarioId());
        assertNull(provider.publicas().getFirst().privada());
        assertThrows(Exception.class, provider::ativa);
        assertEquals(1, calls.get());
    }

    @Test void atualizaEm30SegundosERetiraChavesSomenteConformeJwksConfiavel() throws Exception {
        assertEquals("first", provider.publicas().getFirst().kid());
        var rotated = new RotatingKeyProvider(() -> document("second", key("second", SECOND, NOW.plusSeconds(7200), true)), clock);
        document.set(new ObjectMapper().writeValueAsString(new JwksService(rotated).documento()));
        assertEquals("first", provider.publicas().getFirst().kid());
        clock.set(NOW.plusSeconds(30));
        assertEquals("second", provider.publicas().getFirst().kid());
        assertEquals(2, calls.get());
    }

    @Test void indisponibilidadeDepoisDoCacheNaoUsaChaveObsoleta() {
        provider.publicas();
        status.set(503);
        clock.set(NOW.plusSeconds(30));
        assertThrows(Exception.class, provider::publicas);
        assertThrows(Exception.class, provider::publicas);
    }

    @Test void recusaRedirectJsonAmbiguoOversizedEChavesPrivadas() throws Exception {
        status.set(302);
        assertThrows(Exception.class, provider::atualizar);
        status.set(200);
        for (var invalid : List.of("{}", "{\"keys\":[]}", "x".repeat(65537), document.get() + "{}",
                document.get().replace("\"alg\":\"RS256\"", "\"alg\":\"HS256\""),
                document.get().replace("\"kty\":\"RSA\"", "\"d\":\"private\",\"kty\":\"RSA\""))) {
            document.set(invalid);
            assertThrows(Exception.class, provider::atualizar);
        }
        assertThrows(Exception.class, () -> new TrustedJwksProvider(URI.create("http://localhost/jwks"), clock));
        assertThrows(Exception.class, () -> new TrustedJwksProvider(URI.create("https://user@localhost/jwks"), clock));
    }
}
