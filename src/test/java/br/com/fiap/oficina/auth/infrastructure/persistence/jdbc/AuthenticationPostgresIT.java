package br.com.fiap.oficina.auth.infrastructure.persistence.jdbc;

import br.com.fiap.oficina.auth.application.port.out.*;
import br.com.fiap.oficina.auth.application.usecase.AutenticarUsuarioUseCase;
import br.com.fiap.oficina.auth.domain.enums.Papel;
import br.com.fiap.oficina.auth.domain.exception.IdentityException;
import br.com.fiap.oficina.auth.domain.model.Usuario;
import br.com.fiap.oficina.auth.handler.AuthHandler;
import br.com.fiap.oficina.auth.infrastructure.config.AuthServices;
import br.com.fiap.oficina.auth.infrastructure.security.*;
import br.com.fiap.oficina.auth.support.AuthFixtures.MutableClock;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.*;
import org.postgresql.ds.PGSimpleDataSource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import static br.com.fiap.oficina.auth.support.AuthFixtures.*;
import static br.com.fiap.oficina.auth.infrastructure.security.JwtAndRotationTest.*;
import static br.com.fiap.oficina.auth.domain.exception.IdentityException.Motivo.*;
import static org.junit.jupiter.api.Assertions.*;

@Testcontainers
class AuthenticationPostgresIT {
    @Container static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16.6-alpine");
    private static PGSimpleDataSource datasource;
    private static IdentityTransaction transaction;
    private static final Argon2idPasswordHasher HASHER = new Argon2idPasswordHasher();
    private static String hash;
    private final MutableClock clock = new MutableClock(NOW);
    private static final String BODY = "{\"email\":\"pessoa@example.test\",\"senha\":\"" + SENHA + "\"}";

    @BeforeAll
    static void setup() {
        datasource = new PGSimpleDataSource();
        datasource.setURL(POSTGRES.getJdbcUrl());
        datasource.setUser(POSTGRES.getUsername());
        datasource.setPassword(POSTGRES.getPassword());
        Flyway.configure().dataSource(datasource).load().migrate();
        transaction = new JdbcIdentityTransaction(datasource);
        hash = HASHER.hash(SENHA.toCharArray());
    }

    @BeforeEach
    void clean() throws Exception {
        try (var connection = datasource.getConnection(); var statement = connection.createStatement()) {
            statement.execute("TRUNCATE login_tentativas, usuario_clientes, usuario_papeis, usuarios");
        }
    }

    private Usuario usuario(String passwordHash) {
        var usuario = Usuario.criar("pessoa@example.test", "Pessoa ficticia", "12345678909", passwordHash, NOW.minusSeconds(10));
        usuario.atribuir(Papel.CLIENTE, NOW);
        usuario.atribuir(Papel.MECANICO, NOW);
        transaction.executar(repository -> { repository.inserir(usuario); return null; });
        return usuario;
    }

    private AutenticarUsuarioUseCase login(PasswordHasher hasher) {
        return new AutenticarUsuarioUseCase(transaction, hasher, new Rs256TokenIssuer(provider(clock), clock, ISSUER, AUDIENCE, 900), clock);
    }

    @Test
    void handlerRealAutenticaArgon2PostgresEPapeisEValidaApenasComJwks() throws Exception {
        var usuario = usuario(hash);
        var keys = provider(clock);
        var services = new AuthServices(login(HASHER), new JwksService(keys), new JdbcLoginRateLimiter(datasource));
        var handler = new AuthHandler(() -> services);
        var result = handler.handleRequest(event("POST", "/api/v1/auth/login", BODY), null);
        assertEquals(200, result.getStatusCode());
        var json = new ObjectMapper().readTree(result.getBody());
        var claims = verificar(json.get("accessToken").asText(), publicaDoJwks(services.jwks().documento(), "first"), NOW).getPayload();
        assertEquals(usuario.id().toString(), claims.getSubject());
        assertEquals(List.of("CLIENTE", "MECANICO"), claims.get("roles"));
        transaction.executar(repository -> {
            var loaded = repository.buscarPorId(usuario.id()).orElseThrow();
            loaded.desativar(NOW);
            repository.salvar(loaded);
            return null;
        });
        var inactive = handler.handleRequest(event("POST", "/api/v1/auth/login", BODY), null);
        assertEquals(401, inactive.getStatusCode());
        assertEquals(inactive.getBody(), handler.handleRequest(event("POST", "/api/v1/auth/login", BODY.replace("pessoa@", "ausente@")), null).getBody());
    }

    @Test
    void rehashConcorrenteECompareAndSetNaoPerdemCredencial() throws Exception {
        var usuario = usuario(oldHash());
        var usecase = login(HASHER);
        try (var executor = Executors.newFixedThreadPool(2)) {
            var first = executor.submit(() -> usecase.executar(usuario.email(), SENHA.toCharArray()));
            var second = executor.submit(() -> usecase.executar(usuario.email(), SENHA.toCharArray()));
            assertNotNull(first.get(20, TimeUnit.SECONDS));
            assertNotNull(second.get(20, TimeUnit.SECONDS));
        }
        String current = transaction.executar(repository -> repository.buscarPorId(usuario.id()).orElseThrow().passwordHash());
        assertFalse(HASHER.precisaRehash(current));
        transaction.executar(repository -> {
            repository.buscarPorId(usuario.id()).orElseThrow();
            assertFalse(repository.atualizarHash(usuario.id(), oldHash(), hash, NOW));
            return null;
        });
        assertEquals(current, transaction.executar(repository -> repository.buscarPorId(usuario.id()).orElseThrow().passwordHash()));
        assertEquals(CONCORRENCIA, assertThrows(IdentityException.class, () -> transaction.executar(repository ->
                repository.atualizarHash(usuario.id(), current, hash, NOW))).motivo());
    }

    @Test
    void alteracaoConcorrenteDeSenhaNaoESobrescritaPeloRehash() throws Exception {
        var usuario = usuario(oldHash());
        var entered = new CountDownLatch(1);
        var release = new CountDownLatch(1);
        PasswordHasher delayed = new PasswordHasher() {
            public String hash(char[] senha) { return HASHER.hash(senha); }
            public boolean verificar(char[] senha, String encoded) {
                entered.countDown();
                try { assertTrue(release.await(10, TimeUnit.SECONDS)); }
                catch (InterruptedException exception) { throw new IllegalStateException(exception); }
                return HASHER.verificar(senha, encoded);
            }
            public boolean precisaRehash(String encoded) { return HASHER.precisaRehash(encoded); }
            public String parametros() { return HASHER.parametros(); }
        };
        var usecase = login(delayed);
        String changed = HASHER.hash("outra-senha-ficticia".toCharArray());
        try (var executor = Executors.newFixedThreadPool(2)) {
            var authentication = executor.submit(() -> usecase.executar(usuario.email(), SENHA.toCharArray()));
            assertTrue(entered.await(10, TimeUnit.SECONDS));
            var started = new CountDownLatch(1);
            var change = executor.submit(() -> transaction.executar(repository -> {
                started.countDown();
                var loaded = repository.buscarPorId(usuario.id()).orElseThrow();
                assertTrue(repository.atualizarHash(loaded.id(), loaded.passwordHash(), changed, NOW));
                return null;
            }));
            assertTrue(started.await(10, TimeUnit.SECONDS));
            release.countDown();
            authentication.get(20, TimeUnit.SECONDS);
            change.get(20, TimeUnit.SECONDS);
        } finally { release.countDown(); }
        assertEquals(changed, transaction.executar(repository -> repository.buscarPorId(usuario.id()).orElseThrow().passwordHash()));
        assertThrows(IdentityException.class, () -> login(HASHER).executar(usuario.email(), SENHA.toCharArray()));
        assertNotNull(login(HASHER).executar(usuario.email(), "outra-senha-ficticia".toCharArray()));
    }

    @Test
    void falhaDeChaveReverteRehashEBancoIndisponivelRetorna503() {
        var usuario = usuario(oldHash());
        var usecase = new AutenticarUsuarioUseCase(transaction, HASHER, (id, roles) -> {
            throw new IdentityException(PERSISTENCIA);
        }, clock);
        assertThrows(IdentityException.class, () -> usecase.executar(usuario.email(), SENHA.toCharArray()));
        assertEquals(oldHash(), transaction.executar(repository -> repository.buscarPorId(usuario.id()).orElseThrow().passwordHash()));
        var broken = new PGSimpleDataSource();
        broken.setURL("jdbc:postgresql://127.0.0.1:1/unavailable?connectTimeout=1");
        var handler = new AuthHandler(() -> new AuthServices(new AutenticarUsuarioUseCase(
                new JdbcIdentityTransaction(broken), HASHER, (id, roles) -> { fail(); return null; }, clock),
                new JwksService(provider(clock)), (ip, email) -> {}));
        assertEquals(503, handler.handleRequest(event("POST", "/api/v1/auth/login", BODY), null).getStatusCode());
        assertThrows(IdentityException.class, () -> new JdbcLoginRateLimiter(broken).exigir("192.0.2.1", "a@example.test"));
    }

    @Test
    void limiteDistribuidoContabilizaErrosENaoConfiaEmHeadersDoCliente() throws Exception {
        usuario(hash);
        var limiter = new JdbcLoginRateLimiter(datasource);
        var services = new AuthServices(login(HASHER), new JwksService(provider(clock)), limiter);
        var handler = new AuthHandler(() -> services);
        for (int index = 0; index < 10; index++) {
            var attempt = event("POST", "/api/v1/auth/login", BODY.replace(SENHA, "senha-errada-de-teste"));
            attempt.setHeaders(Map.of("Content-Type", "application/json", "X-Forwarded-For", "192.0.2." + (index + 10)));
            assertEquals(401, handler.handleRequest(attempt, null).getStatusCode());
        }
        assertEquals(429, handler.handleRequest(event("POST", "/api/v1/auth/login", BODY), null).getStatusCode());
        assertEquals(LIMITE_EXCEDIDO, assertThrows(IdentityException.class, () ->
                new JdbcLoginRateLimiter(datasource).exigir("192.0.2.2", "pessoa@example.test")).motivo());
        assertEquals(INVALIDO, assertThrows(IdentityException.class, () -> limiter.exigir("invalid", "a@example.test")).motivo());
        assertEquals(INVALIDO, assertThrows(IdentityException.class, () -> limiter.exigir(null, "a@example.test")).motivo());
        try (var connection = datasource.getConnection(); var statement = connection.createStatement()) {
            statement.execute("TRUNCATE login_tentativas");
        }
        try (var executor = Executors.newFixedThreadPool(4)) {
            List<Callable<Boolean>> attempts = new ArrayList<>();
            for (int index = 0; index < 12; index++) {
                attempts.add(() -> {
                    try { new JdbcLoginRateLimiter(datasource).exigir("192.0.2.1", "a@example.test"); return true; }
                    catch (IdentityException exception) { assertEquals(LIMITE_EXCEDIDO, exception.motivo()); return false; }
                });
            }
            int accepted = 0;
            for (var future : executor.invokeAll(attempts)) { if (future.get()) { accepted++; } }
            assertEquals(10, accepted);
        }
    }

    @Test
    void limitesDeIpEGlobalTambemSaoCompartilhados() throws Exception {
        var first = new JdbcLoginRateLimiter(datasource);
        var second = new JdbcLoginRateLimiter(datasource);
        for (int index = 0; index < 20; index++) {
            first.exigir("192.0.2.9", "pessoa" + index + "@example.test");
        }
        assertEquals(LIMITE_EXCEDIDO, assertThrows(IdentityException.class,
                () -> second.exigir("192.0.2.9", "nova@example.test")).motivo());
        String global = HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256")
                .digest("global".getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        try (var connection = datasource.getConnection(); var statement = connection.prepareStatement(
                "INSERT INTO login_tentativas VALUES (?, date_trunc('minute', CURRENT_TIMESTAMP), 300) ON CONFLICT (chave, janela) DO UPDATE SET tentativas=300")) {
            statement.setString(1, global);
            statement.executeUpdate();
        }
        assertEquals(LIMITE_EXCEDIDO, assertThrows(IdentityException.class,
                () -> second.exigir("192.0.2.10", "outra@example.test")).motivo());
    }

    @Test
    void rotacaoRealComLoginEPublicacaoCompartilhada() {
        var usuario = usuario(hash);
        var source = new java.util.concurrent.atomic.AtomicReference<>(document("first",
                key("first", FIRST, NOW.plusSeconds(120), true), key("second", SECOND, NOW.plusSeconds(7200), true)));
        var first = new RotatingKeyProvider(source::get, clock);
        var second = new RotatingKeyProvider(source::get, clock);
        var login1 = new AutenticarUsuarioUseCase(transaction, HASHER, new Rs256TokenIssuer(first, clock, ISSUER, AUDIENCE, 900), clock);
        String old = login1.executar(usuario.email(), SENHA.toCharArray()).accessToken();
        second.atualizar();
        source.set(document("second", key("first", FIRST, NOW.plusSeconds(120), false),
                key("second", SECOND, NOW.plusSeconds(7200), true)));
        clock.set(NOW.plusSeconds(30));
        var login2 = new AutenticarUsuarioUseCase(transaction, HASHER, new Rs256TokenIssuer(second, clock, ISSUER, AUDIENCE, 900), clock);
        String next = login2.executar(usuario.email(), SENHA.toCharArray()).accessToken();
        var jwks = new JwksService(first).documento();
        verificar(old, publicaDoJwks(jwks, "first"), clock.instant());
        verificar(next, publicaDoJwks(jwks, "second"), clock.instant());
    }
}
