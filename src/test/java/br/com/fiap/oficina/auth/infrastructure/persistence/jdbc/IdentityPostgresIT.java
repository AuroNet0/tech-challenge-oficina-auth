package br.com.fiap.oficina.auth.infrastructure.persistence.jdbc;

import br.com.fiap.oficina.auth.application.port.out.*;
import br.com.fiap.oficina.auth.application.usecase.*;
import br.com.fiap.oficina.auth.domain.enums.Papel;
import br.com.fiap.oficina.auth.domain.exception.IdentityException;
import br.com.fiap.oficina.auth.domain.model.Usuario;
import br.com.fiap.oficina.auth.infrastructure.security.Argon2idPasswordHasher;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.*;
import org.postgresql.ds.PGSimpleDataSource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.*;
import java.sql.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import static br.com.fiap.oficina.auth.domain.exception.IdentityException.Motivo.*;
import static org.junit.jupiter.api.Assertions.*;

@Testcontainers
class IdentityPostgresIT {
    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16.6-alpine");
    private static final Clock CLOCK = Clock.systemUTC();
    private static final ProvisioningAuthorization ALLOWED = (operation, usuario, cliente) -> {};
    private static final Argon2idPasswordHasher HASHER = new Argon2idPasswordHasher();
    private static PGSimpleDataSource datasource;
    private static IdentityTransaction transaction;
    private static String hash;

    @BeforeAll
    static void migrate() {
        datasource = new PGSimpleDataSource();
        datasource.setURL(POSTGRES.getJdbcUrl());
        datasource.setUser(POSTGRES.getUsername());
        datasource.setPassword(POSTGRES.getPassword());
        var flyway = Flyway.configure().dataSource(datasource).load();
        assertEquals(1, flyway.migrate().migrationsExecuted);
        flyway.validate();
        assertEquals(0, flyway.migrate().migrationsExecuted);
        transaction = new JdbcIdentityTransaction(datasource);
        hash = HASHER.hash("senha-ficticia-segura".toCharArray());
    }

    @BeforeEach
    void reset() throws SQLException {
        try (var connection = datasource.getConnection(); var statement = connection.createStatement()) {
            statement.execute("TRUNCATE usuario_clientes, usuario_papeis, usuarios");
        }
    }

    private Usuario criar(String email, String cpf) {
        return Usuario.criar(email, "Pessoa ficticia", cpf, hash, CLOCK.instant());
    }

    private void inserir(Usuario usuario) {
        transaction.executar(repository -> { repository.inserir(usuario); return null; });
    }

    @Test
    void jarShadeExecutaHandlerHashEMigracaoSeparada() throws Exception {
        var output = java.nio.file.Files.createTempFile(java.nio.file.Path.of("target"), "packaged-runtime-", ".log");
        var javaExecutable = java.nio.file.Path.of(System.getProperty("java.home"), "bin", "java").toString();
        var classpath = java.nio.file.Path.of("target", "tech-challenge-oficina-auth.jar").toAbsolutePath()
                + java.io.File.pathSeparator + java.nio.file.Path.of("target", "test-classes").toAbsolutePath();
        var builder = new ProcessBuilder(javaExecutable, "-Dfile.encoding=UTF-8",
                "-Dstdout.encoding=UTF-8", "-Dstderr.encoding=UTF-8", "-cp", classpath,
                "br.com.fiap.oficina.auth.infrastructure.PackagedRuntimeProbe")
                .redirectErrorStream(true).redirectOutput(output.toFile());
        builder.environment().putAll(Map.of("AUTH_DB_HOST", "127.0.0.1",
                "AUTH_DB_PORT", POSTGRES.getMappedPort(5432).toString(),
                "AUTH_DB_NAME", POSTGRES.getDatabaseName(), "AUTH_DB_USER", POSTGRES.getUsername(),
                "AUTH_DB_PASSWORD", POSTGRES.getPassword(), "AUTH_ENVIRONMENT", "local", "AUTH_DB_SSLMODE", "disable"));
        var process = builder.start();
        try {
            assertTrue(process.waitFor(30, TimeUnit.SECONDS));
            var log = java.nio.file.Files.readString(output);
            assertEquals(0, process.exitValue(), log);
            assertTrue(log.contains("PACKAGED_RUNTIME_OK"), log);
        } finally {
            process.destroyForcibly();
        }
    }

    @Test
    void roundTripHashPapeisVinculosIsolamentoEInativacao() {
        var cadastro = new CadastrarUsuarioUseCase(transaction, HASHER, ALLOWED, CLOCK);
        UUID id = cadastro.executar(" Pessoa@example.test ", "Pessoa ficticia", "123.456.789-09",
                "senha-ficticia-segura".toCharArray()).id();
        var segundo = criar("outro@example.test", null);
        inserir(segundo);
        assertEquals(NAO_ENCONTRADO, assertThrows(IdentityException.class,
                () -> new BuscarUsuarioUseCase(transaction, ALLOWED).porEmail("ausente@example.test")).motivo());
        assertTrue(transaction.executar(repository -> repository.buscarPorId(UUID.randomUUID())).isEmpty());
        for (Papel papel : List.of(Papel.CLIENTE, Papel.ATENDENTE, Papel.MECANICO)) {
            new AtribuirPapelUseCase(transaction, ALLOWED, CLOCK).executar(id, papel);
        }
        UUID cliente = UUID.randomUUID();
        new VincularClienteUseCase(transaction, ALLOWED, CLOCK).executar(id, cliente);
        Usuario carregado = transaction.executar(repository -> repository.buscarPorEmail("PESSOA@example.test").orElseThrow());
        assertEquals(id, carregado.id());
        assertEquals("12345678909", carregado.cpf());
        assertTrue(HASHER.verificar("senha-ficticia-segura".toCharArray(), carregado.passwordHash()));
        assertTrue(carregado.podeAcessarCliente(cliente));
        assertEquals(3, carregado.papeis().size());
        var outro = transaction.executar(repository -> repository.buscarPorId(segundo.id()).orElseThrow());
        assertTrue(outro.papeis().isEmpty());
        assertTrue(outro.clientes().isEmpty());
        assertNull(outro.cpf());
        assertFalse(outro.podeAcessarCliente(cliente));
        assertFalse(new DesativarUsuarioUseCase(transaction, ALLOWED, CLOCK).executar(id).ativo());
        var inativo = transaction.executar(repository -> repository.buscarPorId(id).orElseThrow());
        assertFalse(inativo.ativo());
        assertFalse(inativo.podeAcessarCliente(cliente));
        assertEquals(INATIVO, assertThrows(IdentityException.class, () ->
                new AtribuirPapelUseCase(transaction, ALLOWED, CLOCK).executar(id, Papel.GERENTE)).motivo());
    }

    @Test
    void unicidadeEmailCpfERollbackCompleto() {
        var usuario = criar("a@example.test", "12345678909");
        inserir(usuario);
        assertEquals(DUPLICADO, assertThrows(IdentityException.class, () ->
                inserir(criar(" A@EXAMPLE.test ", null))).motivo());
        assertEquals(DUPLICADO, assertThrows(IdentityException.class, () ->
                inserir(criar("b@example.test", "123.456.789-09"))).motivo());
        var cancelado = criar("cancelado@example.test", null);
        cancelado.atribuir(Papel.CLIENTE, CLOCK.instant());
        cancelado.vincular(UUID.randomUUID(), CLOCK.instant());
        assertThrows(IdentityException.class, () -> transaction.executar(repository -> {
            repository.inserir(cancelado);
            repository.inserir(criar("a@example.test", null));
            return null;
        }));
        assertTrue(transaction.executar(repository -> repository.buscarPorId(cancelado.id())).isEmpty());
        assertThrows(IdentityException.class, () -> transaction.executar(repository -> {
            var loaded = repository.buscarPorId(usuario.id()).orElseThrow();
            loaded.atribuir(Papel.GERENTE, CLOCK.instant());
            repository.salvar(loaded);
            throw new IllegalStateException("falha de teste");
        }));
        assertTrue(transaction.executar(repository -> repository.buscarPorId(usuario.id()).orElseThrow().papeis()).isEmpty());
        assertEquals(CONCORRENCIA, assertThrows(IdentityException.class, () -> transaction.executar(repository -> {
            repository.salvar(usuario);
            return null;
        })).motivo());
    }

    @Test
    void constraintsPapeisVinculosEIndices() throws SQLException {
        var usuario = criar("a@example.test", null);
        inserir(usuario);
        assertSqlFails("INSERT INTO usuario_papeis VALUES (?, 'ROOT')", usuario.id());
        assertSqlFails("INSERT INTO usuario_clientes (usuario_id, cliente_id, criado_em) VALUES (?, gen_random_uuid(), now())", usuario.id());
        new AtribuirPapelUseCase(transaction, ALLOWED, CLOCK).executar(usuario.id(), Papel.CLIENTE);
        assertSqlFails("INSERT INTO usuario_papeis VALUES (?, 'CLIENTE')", usuario.id());
        UUID cliente = UUID.randomUUID();
        new VincularClienteUseCase(transaction, ALLOWED, CLOCK).executar(usuario.id(), cliente);
        assertSqlFails("INSERT INTO usuario_clientes (usuario_id, cliente_id, criado_em) SELECT usuario_id, cliente_id, criado_em FROM usuario_clientes WHERE usuario_id = ?", usuario.id());
        assertSqlFails("UPDATE usuarios SET email = 'A@example.test' WHERE id = ?", usuario.id());
        assertSqlFails("UPDATE usuarios SET cpf = 'abc' WHERE id = ?", usuario.id());
        assertSqlFails("UPDATE usuarios SET password_hash = 'texto puro' WHERE id = ?", usuario.id());
        assertSqlFails("UPDATE usuarios SET atualizado_em = criado_em - interval '1 second' WHERE id = ?", usuario.id());
        try (var connection = datasource.getConnection();
             var statement = connection.prepareStatement("SELECT indexname FROM pg_indexes WHERE schemaname='public'");
             var result = statement.executeQuery()) {
            Set<String> indexes = new HashSet<>();
            while (result.next()) { indexes.add(result.getString(1)); }
            assertTrue(indexes.containsAll(Set.of("usuarios_pkey", "usuarios_email_key", "usuarios_cpf_key",
                    "usuario_papeis_pkey", "usuario_clientes_pkey", "idx_usuario_papeis_papel", "idx_usuario_clientes_cliente")));
        }
    }

    private void assertSqlFails(String sql, UUID id) {
        assertThrows(SQLException.class, () -> {
            try (var connection = datasource.getConnection(); var statement = connection.prepareStatement(sql)) {
                statement.setObject(1, id);
                statement.executeUpdate();
            }
        });
    }

    @Test
    void concorrenciaSerializaPapeisEVinculosERejeitaDuplicatas() throws Exception {
        var usuario = criar("a@example.test", null);
        inserir(usuario);
        var papel = new AtribuirPapelUseCase(transaction, ALLOWED, CLOCK);
        assertEquals(Set.of("OK", "DUPLICADO"), competir(() -> papel.executar(usuario.id(), Papel.CLIENTE)));
        var vinculo = new VincularClienteUseCase(transaction, ALLOWED, CLOCK);
        UUID cliente = UUID.randomUUID();
        assertEquals(Set.of("OK", "DUPLICADO"), competir(() -> vinculo.executar(usuario.id(), cliente)));
        var loaded = transaction.executar(repository -> repository.buscarPorId(usuario.id()).orElseThrow());
        assertEquals(Set.of(Papel.CLIENTE), loaded.papeis());
        assertEquals(1, loaded.clientes().size());
        assertEquals(Set.of("OK", "DUPLICADO"), competir(() -> {
            inserir(criar("unico@example.test", null));
            return null;
        }));
    }

    private Set<String> competir(Callable<?> operation) throws Exception {
        var start = new CountDownLatch(1);
        try (var executor = Executors.newFixedThreadPool(2)) {
            List<Future<String>> futures = new ArrayList<>();
            for (int index = 0; index < 2; index++) {
                futures.add(executor.submit(() -> {
                    start.await();
                    try {
                        operation.call();
                        return "OK";
                    } catch (IdentityException exception) {
                        return exception.motivo().name();
                    }
                }));
            }
            start.countDown();
            return Set.of(futures.get(0).get(20, TimeUnit.SECONDS), futures.get(1).get(20, TimeUnit.SECONDS));
        }
    }
}
