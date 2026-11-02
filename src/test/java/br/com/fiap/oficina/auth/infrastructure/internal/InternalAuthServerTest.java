package br.com.fiap.oficina.auth.infrastructure.internal;

import br.com.fiap.oficina.auth.application.port.out.IdentityTransaction;
import br.com.fiap.oficina.auth.domain.enums.Papel;
import br.com.fiap.oficina.auth.domain.exception.IdentityException;
import br.com.fiap.oficina.auth.domain.model.Usuario;
import br.com.fiap.oficina.auth.infrastructure.security.*;
import br.com.fiap.oficina.auth.support.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.net.*;
import java.net.http.*;
import java.nio.file.Path;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import static br.com.fiap.oficina.auth.support.AuthFixtures.*;
import static org.junit.jupiter.api.Assertions.*;

class InternalAuthServerTest {
    @TempDir static Path directory;
    static TestTls certificates;
    final Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
    final UUID clientId = UUID.randomUUID();
    final Usuario user = Usuario.criar("cliente@example.test", "Nome privado", null, oldHash(), NOW);
    final Store store = new Store(user);
    final AtomicBoolean ready = new AtomicBoolean(true);
    InternalAuthServer server;

    @BeforeAll static void certificates() throws Exception { certificates = new TestTls(directory); }

    @BeforeEach void start() throws Exception {
        user.atribuir(Papel.CLIENTE, NOW);
        user.vincular(clientId, NOW);
        start(store);
    }

    void start(IdentityTransaction transaction) throws Exception {
        server = new InternalAuthServer(new InetSocketAddress("localhost", 0), new InternalTls(certificates.environment()),
                transaction, new InternalUserTokenVerifier(provider(clock), ISSUER, AUDIENCE, clock), clock,
                () -> { if (!ready.get()) { throw new IllegalStateException(); } });
        server.start();
    }

    @AfterEach void stop() { server.close(); }

    String token(UUID subject) {
        return new Rs256TokenIssuer(provider(clock), clock, ISSUER, AUDIENCE, 60).emitir(subject, Set.of(Papel.CLIENTE)).accessToken();
    }

    String body(UUID subject, UUID target) throws Exception {
        return new ObjectMapper().writeValueAsString(Map.of("clienteId", target.toString(), "userAccessToken", token(subject),
                "requestId", clientId.toString(), "issuedAt", NOW.toString()));
    }

    HttpResponse<String> request(String identity, String path, String method, String body) throws Exception {
        try (var client = HttpClient.newBuilder().sslContext(certificates.context(identity))
                .connectTimeout(Duration.ofSeconds(2)).build()) {
            return client.send(HttpRequest.newBuilder(URI.create("https://localhost:" + server.port() + path))
                    .timeout(Duration.ofSeconds(5)).header("Content-Type", "application/json")
                    .method(method, HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
        }
    }

    @Test void osAutenticadoRecebeSomenteDecisaoECorrelacao() throws Exception {
        var response = request("os", InternalAuthServer.ACCESS_PATH, "POST", body(user.id(), clientId));
        assertEquals(200, response.statusCode());
        assertEquals("{\"autorizado\":true}", response.body());
        assertEquals("no-store", response.headers().firstValue("Cache-Control").orElseThrow());
        assertEquals(clientId.toString(), response.headers().firstValue("X-Correlation-ID").orElseThrow());
        assertFalse(response.body().contains(user.email()));
        assertFalse(response.body().contains(user.nome()));
    }

    @Test void ausenciaCertificadoNaoAutenticaMesmoComHeadersDeclarativos() throws Exception {
        assertEquals(401, request(null, InternalAuthServer.ACCESS_PATH, "POST", body(user.id(), clientId)).statusCode());
    }

    @Test void outroServicoDaMesmaCaRecebe403() throws Exception {
        assertEquals(403, request("billing", InternalAuthServer.ACCESS_PATH, "POST", body(user.id(), clientId)).statusCode());
    }

    @Test void cadeiaDesconhecidaEExpiradaNaoAutorizam() throws Exception {
        for (var identity : List.of("unknown", "expired")) {
            try {
                var response = request(identity, InternalAuthServer.ACCESS_PATH, "POST", body(user.id(), clientId));
                assertEquals(401, response.statusCode());
            } catch (java.io.IOException exception) {
                assertNotNull(exception);
            }
        }
    }

    @Test void consultaVinculoAtualSemCachePositivo() throws Exception {
        assertEquals("{\"autorizado\":true}", request("os", InternalAuthServer.ACCESS_PATH, "POST", body(user.id(), clientId)).body());
        user.desativar(NOW);
        assertEquals("{\"autorizado\":false}", request("os", InternalAuthServer.ACCESS_PATH, "POST", body(user.id(), clientId)).body());
    }

    @Test void outroSubOuClienteSemVinculoRecebeNegativa() throws Exception {
        assertEquals("{\"autorizado\":false}", request("os", InternalAuthServer.ACCESS_PATH, "POST", body(UUID.randomUUID(), clientId)).body());
        assertEquals("{\"autorizado\":false}", request("os", InternalAuthServer.ACCESS_PATH, "POST", body(user.id(), UUID.randomUUID())).body());
        store.usuario = new Usuario(user.id(), user.email(), user.nome(), null, oldHash(), true, NOW, NOW, Set.of(), List.of());
        assertEquals("{\"autorizado\":false}", request("os", InternalAuthServer.ACCESS_PATH, "POST", body(store.usuario.id(), clientId)).body());
    }

    @Test void identidadeAutodeclaradaEPayloadMalformadoSaoRejeitados() throws Exception {
        var valid = body(user.id(), clientId);
        for (var invalid : List.of(valid.replaceFirst("\\{", "{\"usuarioId\":\"" + UUID.randomUUID() + "\","),
                "{}", "x".repeat(12289))) {
            assertEquals(400, request("os", InternalAuthServer.ACCESS_PATH, "POST", invalid).statusCode());
        }
        var invalidToken = new ObjectMapper().readTree(valid);
        ((com.fasterxml.jackson.databind.node.ObjectNode) invalidToken).put("userAccessToken", "bad");
        assertEquals(401, request("os", InternalAuthServer.ACCESS_PATH, "POST", invalidToken.toString()).statusCode());
    }

    @Test void falhaPersistenciaRetorna503() throws Exception {
        server.close();
        start(new IdentityTransaction() {
            public <T> T executar(java.util.function.Function<br.com.fiap.oficina.auth.application.port.out.UsuarioRepository, T> operation) {
                throw new IdentityException(IdentityException.Motivo.PERSISTENCIA);
            }
        });
        var response = request("os", InternalAuthServer.ACCESS_PATH, "POST", body(user.id(), clientId));
        assertEquals(503, response.statusCode());
        assertEquals("{}", response.body());
    }

    @Test void probesSemCertificadoSeparamProntidaoDeVidaERotasPublicasAusentes() throws Exception {
        var env = new HashMap<>(certificates.environment());
        env.put("AUTH_INTERNAL_PORT", Integer.toString(server.port()));
        assertTrue(InternalHealthProbe.ready(env));
        assertEquals(200, request(null, "/health/live", "GET", "").statusCode());
        assertEquals(200, request(null, "/health/ready", "GET", "").statusCode());
        ready.set(false);
        assertFalse(InternalHealthProbe.ready(env));
        assertFalse(InternalHealthProbe.ready(Map.of()));
        assertEquals(503, request(null, "/health/ready", "GET", "").statusCode());
        assertEquals(200, request(null, "/health/live", "GET", "").statusCode());
        for (var path : List.of("/api/v1/auth/login", "/.well-known/jwks.json", "/internal/client-access")) {
            assertEquals(404, request(null, path, "POST", "{}").statusCode());
        }
        assertEquals(400, request("os", InternalAuthServer.ACCESS_PATH, "GET", "").statusCode());
    }

    @Test void configuracaoTlsInseguraFalhaAntesDeEscutar() {
        assertThrows(Exception.class, () -> new InternalTls(Map.of()));
        var env = new HashMap<>(certificates.environment());
        env.put("AUTH_INTERNAL_OS_SUBJECT", "CN=billing-service");
        assertThrows(Exception.class, () -> new InternalTls(env));
        env.put("AUTH_INTERNAL_OS_SUBJECT", "CN=os-service");
        env.put("AUTH_INTERNAL_KEYSTORE_PASSWORD", "wrong-password");
        assertThrows(Exception.class, () -> new InternalTls(env));
    }
}
