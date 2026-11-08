package br.com.fiap.oficina.auth.infrastructure.internal;

import br.com.fiap.oficina.auth.domain.enums.Papel;
import br.com.fiap.oficina.auth.domain.model.Usuario;
import br.com.fiap.oficina.auth.infrastructure.persistence.jdbc.JdbcIdentityTransaction;
import br.com.fiap.oficina.auth.infrastructure.security.JwksService;
import br.com.fiap.oficina.auth.support.TestTls;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.api.io.TempDir;
import org.postgresql.ds.PGSimpleDataSource;
import org.testcontainers.containers.*;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.MountableFile;
import java.net.*;
import java.net.http.*;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.*;
import java.util.*;
import static br.com.fiap.oficina.auth.support.AuthFixtures.*;
import static org.junit.jupiter.api.Assertions.*;

@EnabledIfSystemProperty(named = "auth.internal.image", matches = ".+")
class InternalContainerIT {
    @TempDir Path directory;

    @Test void imagemProdutivaComPostgres17MtlsJwtFalhaDeBancoESigterm() throws Exception {
        String image = System.getProperty("auth.internal.image");
        var tls = new TestTls(directory);
        var originalPermissions = Files.getFileStore(directory).supportsFileAttributeView("posix")
                ? Files.getPosixFilePermissions(directory) : null;
        var serverMount = tls.serverMount();
        try (var files = Files.list(serverMount)) {
            assertEquals(Set.of("server.p12", "trust.p12"), files.map(path -> path.getFileName().toString()).collect(java.util.stream.Collectors.toSet()));
        }
        if (originalPermissions != null) {
            assertEquals(originalPermissions, Files.getPosixFilePermissions(directory));
            assertEquals(PosixFilePermissions.fromString("rwxr-xr-x"), Files.getPosixFilePermissions(serverMount));
            for (String name : List.of("server.p12", "trust.p12")) {
                assertEquals(PosixFilePermissions.fromString("r--r--r--"), Files.getPosixFilePermissions(serverMount.resolve(name)));
            }
        }
        var jwksMount = tls.serverMount();
        Files.writeString(jwksMount.resolve("jwks.json"), new ObjectMapper().writeValueAsString(
                new JwksService(provider(Clock.fixed(NOW, ZoneOffset.UTC))).documento()));
        try (var postgres = new PostgreSQLContainer<>("postgres:17.6-alpine")) {
            postgres.addExposedPorts(8443, 9443);
            postgres.start();
            var datasource = new PGSimpleDataSource();
            datasource.setURL(postgres.getJdbcUrl());
            datasource.setUser(postgres.getUsername());
            datasource.setPassword(postgres.getPassword());
            var flyway = Flyway.configure().dataSource(datasource).cleanDisabled(true).load();
            assertEquals(2, flyway.migrate().migrationsExecuted);
            flyway.validate();
            var now = Instant.now();
            var user = Usuario.criar("ephemeral@example.test", "Pessoa teste", null, oldHash(), now);
            var clientId = UUID.randomUUID();
            user.atribuir(Papel.CLIENTE, now);
            user.vincular(clientId, now);
            new JdbcIdentityTransaction(datasource).executar(repository -> { repository.inserir(user); return null; });
            try (var jwks = new GenericContainer<>(image)
                    .withNetworkMode("container:" + postgres.getContainerId())
                    .withCopyFileToContainer(MountableFile.forHostPath(jwksMount, 0755), "/tls")
                    .withCopyFileToContainer(MountableFile.forHostPath(Path.of("target/test-classes").toAbsolutePath(), 0755), "/fixtures")
                    .withCreateContainerCmdModifier(command -> command.withEntrypoint("java", "-cp", "/fixtures:/app/app.jar",
                            ContainerJwksMain.class.getName()))
                    .waitingFor(Wait.forLogMessage(".*JWKS_FIXTURE_READY.*", 1))) {
                ContainerStartupDiagnostics.start(jwks, TestTls.PASSWORD, postgres.getPassword());
                var env = new HashMap<String, String>();
                env.put("AUTH_ENVIRONMENT", "local");
                env.put("AUTH_DB_HOST", "127.0.0.1");
                env.put("AUTH_DB_NAME", postgres.getDatabaseName());
                env.put("AUTH_DB_USER", postgres.getUsername());
                env.put("AUTH_DB_PASSWORD", postgres.getPassword());
                env.put("AUTH_DB_SSLMODE", "disable");
                env.put("AUTH_JWT_ISSUER", ISSUER);
                env.put("AUTH_JWT_AUDIENCE", AUDIENCE);
                env.put("AUTH_JWKS_URI", "https://localhost:9443/jwks");
                env.put("AUTH_INTERNAL_KEYSTORE", "/tls/server.p12");
                env.put("AUTH_INTERNAL_KEYSTORE_PASSWORD", TestTls.PASSWORD);
                env.put("AUTH_INTERNAL_TRUSTSTORE", "/tls/trust.p12");
                env.put("AUTH_INTERNAL_TRUSTSTORE_PASSWORD", TestTls.PASSWORD);
                env.put("JAVA_TOOL_OPTIONS", "-Xmx384m -Djavax.net.ssl.trustStore=/tls/trust.p12 -Djavax.net.ssl.trustStorePassword=" + TestTls.PASSWORD);
                try (var runtime = new GenericContainer<>(image)
                        .withNetworkMode("container:" + postgres.getContainerId()).withEnv(env)
                        .withFileSystemBind(serverMount.toAbsolutePath().toString(), "/tls", BindMode.READ_ONLY)
                        .withCreateContainerCmdModifier(command -> command.getHostConfig().withReadonlyRootfs(true)
                                .withMemory(768L * 1024 * 1024).withNanoCPUs(1_000_000_000L)
                                .withTmpFs(Map.of("/tmp", "rw,noexec,nosuid,size=64m")))
                        .waitingFor(Wait.forLogMessage(".*AUTH_INTERNAL_STARTED.*", 1));
                     var client = HttpClient.newBuilder().sslContext(tls.context("os")).build();
                     var probe = HttpClient.newBuilder().sslContext(tls.context(null)).build()) {
                    ContainerStartupDiagnostics.start(runtime, TestTls.PASSWORD, postgres.getPassword());
                    String base = "https://localhost:" + postgres.getMappedPort(8443);
                    var health = HttpRequest.newBuilder(URI.create(base + "/health/ready")).GET().timeout(Duration.ofSeconds(5)).build();
                    org.testcontainers.shaded.org.awaitility.Awaitility.await().atMost(Duration.ofSeconds(20)).until(() -> {
                        try { return probe.send(health, HttpResponse.BodyHandlers.ofString()).statusCode() == 200; }
                        catch (Exception exception) { return false; }
                    });
                    assertEquals(200, probe.send(health, HttpResponse.BodyHandlers.ofString()).statusCode());
                    assertEquals("10001", runtime.execInContainer("id", "-u").getStdout().strip());
                    assertTrue(runtime.getContainerInfo().getMounts().stream().anyMatch(mount ->
                            "/tls".equals(mount.getDestination().getPath()) && Boolean.FALSE.equals(mount.getRW())));
                    assertEquals(0, runtime.execInContainer("sh", "-ec",
                            "test -r /tls/server.p12 && test -r /tls/trust.p12 && test ! -e /tls/ca.p12 && test ! -e /tls/os.p12 && ! touch /tls/write-check").getExitCode());
                    var probeResult = runtime.execInContainer("java", "-cp", "/app/app.jar", InternalHealthProbe.class.getName());
                    assertEquals(0, probeResult.getExitCode(), probeResult.getStderr().replace(TestTls.PASSWORD, "[redacted]"));
                    assertDecision(client, base, user.id(), clientId, true);
                    assertDecision(client, base, user.id(), UUID.randomUUID(), false);
                    assertEquals(401, probe.send(access(base, user.id(), clientId), HttpResponse.BodyHandlers.ofString()).statusCode());
                    postgres.getDockerClient().pauseContainerCmd(postgres.getContainerId()).exec();
                    try {
                        var denied = client.send(access(base, user.id(), clientId), HttpResponse.BodyHandlers.ofString());
                        assertEquals(503, denied.statusCode());
                        assertEquals("{}", denied.body());
                        assertEquals(503, probe.send(health, HttpResponse.BodyHandlers.ofString()).statusCode());
                        assertEquals(200, probe.send(HttpRequest.newBuilder(URI.create(base + "/health/live")).GET().build(),
                                HttpResponse.BodyHandlers.ofString()).statusCode());
                    } finally { postgres.getDockerClient().unpauseContainerCmd(postgres.getContainerId()).exec(); }
                    runtime.getDockerClient().stopContainerCmd(runtime.getContainerId()).withTimeout(15).exec();
                    assertTrue(runtime.getLogs().contains("AUTH_INTERNAL_STOPPED"));
                    var stopped = runtime.getDockerClient().inspectContainerCmd(runtime.getContainerId()).exec();
                    assertEquals(143L, stopped.getState().getExitCodeLong());
                    runtime.getDockerClient().startContainerCmd(runtime.getContainerId()).exec();
                    org.testcontainers.shaded.org.awaitility.Awaitility.await().atMost(Duration.ofSeconds(20)).until(() -> {
                        try { return probe.send(health, HttpResponse.BodyHandlers.ofString()).statusCode() == 200; }
                        catch (Exception exception) { return false; }
                    });
                    assertDecision(client, base, user.id(), clientId, true);
                }
            }
        }
    }

    private HttpRequest access(String base, UUID user, UUID client) throws Exception {
        var now = Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
        String token = Jwts.builder().header().type("JWT").keyId("first").and().issuer(ISSUER).subject(user.toString())
                .audience().add(AUDIENCE).and().issuedAt(Date.from(now)).notBefore(Date.from(now))
                .expiration(Date.from(now.plusSeconds(60))).id(UUID.randomUUID().toString()).claim("roles", List.of("CLIENTE"))
                .signWith(FIRST.getPrivate(), Jwts.SIG.RS256).compact();
        String body = new ObjectMapper().writeValueAsString(Map.of("clienteId", client.toString(), "userAccessToken", token,
                "requestId", UUID.randomUUID().toString(), "issuedAt", Instant.now().toString()));
        return HttpRequest.newBuilder(URI.create(base + InternalAuthServer.ACCESS_PATH)).timeout(Duration.ofSeconds(3))
                .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(body)).build();
    }

    private void assertDecision(HttpClient http, String base, UUID user, UUID client, boolean expected) throws Exception {
        var response = http.send(access(base, user, client), HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode());
        assertEquals("{\"autorizado\":" + expected + "}", response.body());
    }
}
