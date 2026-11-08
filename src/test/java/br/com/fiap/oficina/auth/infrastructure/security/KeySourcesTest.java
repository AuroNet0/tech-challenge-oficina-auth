package br.com.fiap.oficina.auth.infrastructure.security;

import br.com.fiap.oficina.auth.domain.exception.IdentityException;
import br.com.fiap.oficina.auth.infrastructure.config.AuthBootstrap;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.*;
import java.nio.file.*;
import java.lang.reflect.Proxy;
import java.time.*;
import java.util.*;
import static br.com.fiap.oficina.auth.support.AuthFixtures.*;
import static org.junit.jupiter.api.Assertions.*;

class KeySourcesTest {
    @TempDir Path directory;

    @Test
    void arquivoLocalExigeOptInENaoPodeRodarNaLambda() throws Exception {
        Path file = directory.resolve("local-key.json");
        String json = document("first", key("first", FIRST, NOW.plusSeconds(3600), true));
        Files.writeString(file, json);
        var env = new HashMap<>(Map.of("AUTH_ENVIRONMENT", "local", "AUTH_LOCAL_KEY_FILE", file.toString()));
        assertEquals(json, new LocalKeySource(env).get());
        env.put("AWS_LAMBDA_FUNCTION_NAME", "auth");
        assertThrows(IllegalArgumentException.class, () -> new LocalKeySource(env));
        assertThrows(IllegalArgumentException.class, () -> new LocalKeySource(Map.of()));
        assertThrows(IllegalArgumentException.class, () -> new LocalKeySource(Map.of("AUTH_ENVIRONMENT", "local", "AUTH_LOCAL_KEY_FILE", "relative")));
        env.remove("AWS_LAMBDA_FUNCTION_NAME");
        Files.writeString(file, "x".repeat(65537));
        assertThrows(IdentityException.class, () -> new LocalKeySource(env).get());
        Files.delete(file);
        assertThrows(IdentityException.class, () -> new LocalKeySource(env).get());
    }

    @Test
    void secretsManagerUsaAwscurrentSemPropagarErrosOuSegredos() {
        var client = (SecretsManagerClient) Proxy.newProxyInstance(getClass().getClassLoader(),
                new Class<?>[]{SecretsManagerClient.class}, (proxy, method, args) -> {
                    if (method.getName().equals("getSecretValue")) {
                        var request = (GetSecretValueRequest) args[0];
                        assertEquals("AWSCURRENT", request.versionStage());
                        assertEquals("test-secret-id", request.secretId());
                        return GetSecretValueResponse.builder().secretString("documento-fixture").build();
                    }
                    return null;
                });
        assertEquals("documento-fixture", new SecretsManagerKeySource(client, "test-secret-id").get());
        assertThrows(IllegalArgumentException.class, () -> new SecretsManagerKeySource(client, ""));
        var broken = (SecretsManagerClient) Proxy.newProxyInstance(getClass().getClassLoader(),
                new Class<?>[]{SecretsManagerClient.class}, (proxy, method, args) -> {
                    throw new IllegalStateException("sensitive");
                });
        var exception = assertThrows(IdentityException.class, () -> new SecretsManagerKeySource(broken, "test").get());
        assertFalse(exception.getMessage().contains("sensitive"));
        assertNull(exception.getCause());
    }

    @Test
    void geraChavesLocaisSomentePorComandoExplicitoSemSobrescrever() throws Exception {
        var file = directory.resolve("generated.json");
        br.com.fiap.oficina.auth.infrastructure.config.GenerateLocalKeys.gerar(file, Clock.fixed(NOW, ZoneOffset.UTC));
        var clock = new MutableClock(NOW);
        var provider = new RotatingKeyProvider(() -> {
            try { return Files.readString(file); } catch (Exception exception) { throw new IllegalStateException(exception); }
        }, clock);
        assertEquals(1, provider.publicas().size());
        assertThrows(IdentityException.class, provider::ativa);
        clock.set(NOW.plusSeconds(90));
        assertNotNull(provider.ativa());
        assertThrows(FileAlreadyExistsException.class, () ->
                br.com.fiap.oficina.auth.infrastructure.config.GenerateLocalKeys.gerar(file, clock));
        assertThrows(IllegalArgumentException.class, () ->
                br.com.fiap.oficina.auth.infrastructure.config.GenerateLocalKeys.gerar(Path.of("relative"), clock));
    }

    @Test
    void bootstrapRecusaConfiguracaoIncompletaSemFallbackLegado() {
        assertThrows(IllegalArgumentException.class, () -> AuthBootstrap.criar(Map.of(), Clock.systemUTC()));
        assertThrows(IllegalArgumentException.class, () -> AuthBootstrap.criar(Map.of("AUTH_KEY_PROVIDER", "unknown"), Clock.systemUTC()));
        assertThrows(IllegalArgumentException.class, () -> AuthBootstrap.criar(Map.of("AUTH_KEY_PROVIDER", "local-file"), Clock.systemUTC()));
        assertThrows(IllegalArgumentException.class, () -> AuthBootstrap.criar(Map.of("AUTH_KEY_PROVIDER", "secrets-manager"), Clock.systemUTC()));
    }

    @Test
    void bootstrapLocalReutilizaServicosSemAbrirConexaoParaJwks() throws Exception {
        var file = directory.resolve("bootstrap.json");
        Files.writeString(file, document("first", key("first", FIRST, NOW.plusSeconds(3600), true)));
        var env = new HashMap<>(Map.of("AUTH_ENVIRONMENT", "local", "AUTH_KEY_PROVIDER", "local-file",
                "AUTH_LOCAL_KEY_FILE", file.toString(), "AUTH_JWT_ISSUER", ISSUER, "AUTH_JWT_AUDIENCE", AUDIENCE,
                "AUTH_DB_HOST", "127.0.0.1", "AUTH_DB_SSLMODE", "disable", "AUTH_DB_NAME", "auth_test",
                "AUTH_DB_USER", "auth_test", "AUTH_DB_PASSWORD", "fixture-apenas-local"));
        try (var services = AuthBootstrap.criar(env, Clock.fixed(NOW, ZoneOffset.UTC))) {
            assertEquals(1, ((List<?>) services.jwks().documento().get("keys")).size());
            assertSame(services.login(), services.login());
        }
        env.remove("AUTH_DB_PASSWORD");
        assertThrows(IllegalArgumentException.class, () -> AuthBootstrap.criar(env, Clock.fixed(NOW, ZoneOffset.UTC)));
    }
}
