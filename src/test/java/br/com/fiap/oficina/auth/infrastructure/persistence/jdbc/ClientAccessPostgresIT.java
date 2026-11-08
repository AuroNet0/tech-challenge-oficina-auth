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
import java.sql.SQLException;
import java.time.Clock;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.*;
import static br.com.fiap.oficina.auth.domain.exception.IdentityException.Motivo.*;
import static org.junit.jupiter.api.Assertions.*;

@Testcontainers
class ClientAccessPostgresIT {
    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16.6-alpine");
    private static final Clock CLOCK = Clock.systemUTC();
    private static final ProvisioningAuthorization PROVISIONING = (operation, usuario, cliente) -> {};
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
        assertEquals(2, flyway.migrate().migrationsExecuted);
        flyway.validate();
        transaction = new JdbcIdentityTransaction(datasource);
        hash = new Argon2idPasswordHasher().hash("senha-ficticia-segura".toCharArray());
    }

    @BeforeEach
    void reset() throws SQLException {
        try (var connection = datasource.getConnection(); var statement = connection.createStatement()) {
            statement.execute("TRUNCATE usuario_clientes, usuario_papeis, usuarios");
        }
    }

    private Usuario criar(String email) {
        var usuario = Usuario.criar(email, "Pessoa ficticia", null, hash, CLOCK.instant());
        transaction.executar(repository -> { repository.inserir(usuario); return null; });
        return usuario;
    }

    private VerificarAcessoClienteUseCase checker(UUID usuarioId) {
        return new VerificarAcessoClienteUseCase(transaction,
                alvo -> new IdentidadeAcessoCliente(usuarioId, "os-service", alvo, CLOCK.instant().plusSeconds(60)),
                Set.of("os-service"), CLOCK);
    }

    private void vincular(UUID usuarioId, UUID clienteId) {
        new VincularClienteUseCase(transaction, PROVISIONING, CLOCK).executar(usuarioId, clienteId);
    }

    @Test
    void resolveRelacaoMuitosParaMuitosSemAlterarPersistencia() throws Exception {
        var primeiro = criar("primeiro@example.test");
        var segundo = criar("segundo@example.test");
        UUID cliente = UUID.randomUUID();
        UUID outroCliente = UUID.randomUUID();
        var papel = new AtribuirPapelUseCase(transaction, PROVISIONING, CLOCK);
        papel.executar(primeiro.id(), Papel.CLIENTE);
        papel.executar(segundo.id(), Papel.CLIENTE);
        vincular(primeiro.id(), cliente);
        vincular(primeiro.id(), outroCliente);
        vincular(segundo.id(), cliente);
        assertTrue(checker(primeiro.id()).executar(cliente.toString()).autorizado());
        assertTrue(checker(primeiro.id()).executar(outroCliente.toString()).autorizado());
        assertTrue(checker(segundo.id()).executar(cliente.toString()).autorizado());
        assertFalse(checker(segundo.id()).executar(outroCliente.toString()).autorizado());
        assertFalse(checker(primeiro.id()).executar(UUID.randomUUID().toString()).autorizado());
        assertFalse(checker(UUID.randomUUID()).executar(cliente.toString()).autorizado());
        var semPapel = criar("sem-papel@example.test");
        assertFalse(checker(semPapel.id()).executar(cliente.toString()).autorizado());
        try (var connection = datasource.getConnection(); var statement = connection.createStatement();
             var rows = statement.executeQuery("SELECT count(*) FROM usuario_clientes")) {
            assertTrue(rows.next());
            assertEquals(3, rows.getInt(1));
        }
    }

    @Test
    void consultaEstadoAtualSemCacheEObservaRollbackDeInativacao() {
        var usuario = criar("cliente@example.test");
        UUID cliente = UUID.randomUUID();
        new AtribuirPapelUseCase(transaction, PROVISIONING, CLOCK).executar(usuario.id(), Papel.CLIENTE);
        vincular(usuario.id(), cliente);
        var acesso = checker(usuario.id());
        assertTrue(acesso.executar(cliente.toString()).autorizado());
        assertThrows(IdentityException.class, () -> transaction.executar(repository -> {
            var loaded = repository.buscarPorId(usuario.id()).orElseThrow();
            loaded.desativar(CLOCK.instant());
            repository.salvar(loaded);
            throw new IdentityException(PERSISTENCIA);
        }));
        assertTrue(acesso.executar(cliente.toString()).autorizado());
        new DesativarUsuarioUseCase(transaction, PROVISIONING, CLOCK).executar(usuario.id());
        assertFalse(acesso.executar(cliente.toString()).autorizado());
    }

    @Test
    void aguardaLockEConsideraInativacaoConcorrenteConfirmada() throws Exception {
        var usuario = criar("concorrente@example.test");
        UUID cliente = UUID.randomUUID();
        new AtribuirPapelUseCase(transaction, PROVISIONING, CLOCK).executar(usuario.id(), Papel.CLIENTE);
        vincular(usuario.id(), cliente);
        var locked = new CountDownLatch(1);
        var release = new CountDownLatch(1);
        try (var executor = Executors.newFixedThreadPool(2)) {
            var desativacao = executor.submit(() -> transaction.executar(repository -> {
                var loaded = repository.buscarPorId(usuario.id()).orElseThrow();
                loaded.desativar(CLOCK.instant());
                repository.salvar(loaded);
                locked.countDown();
                try {
                    if (!release.await(10, TimeUnit.SECONDS)) { throw new IllegalStateException("Timeout de teste"); }
                } catch (InterruptedException exception) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException("Teste interrompido");
                }
                return null;
            }));
            try {
                assertTrue(locked.await(5, TimeUnit.SECONDS));
                var decisao = executor.submit(() -> checker(usuario.id()).executar(cliente.toString()));
                esperarLeituraBloqueada();
                assertFalse(decisao.isDone());
                release.countDown();
                desativacao.get(10, TimeUnit.SECONDS);
                assertFalse(decisao.get(10, TimeUnit.SECONDS).autorizado());
            } finally {
                release.countDown();
            }
        }
    }

    private void esperarLeituraBloqueada() throws Exception {
        long prazo = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        try (var connection = datasource.getConnection(); var statement = connection.prepareStatement("""
                SELECT EXISTS (SELECT 1 FROM pg_stat_activity
                WHERE datname = current_database() AND wait_event_type = 'Lock'
                AND query LIKE 'SELECT * FROM usuarios WHERE id =%')
                """)) {
            while (System.nanoTime() < prazo) {
                try (var rows = statement.executeQuery()) {
                    assertTrue(rows.next());
                    if (rows.getBoolean(1)) { return; }
                }
                Thread.sleep(10);
            }
        }
        fail("Leitura deveria esperar o lock do usuario");
    }

    @Test
    void bancoIndisponivelNaoProduzDecisaoDeVinculo() {
        var broken = new PGSimpleDataSource();
        broken.setURL("jdbc:postgresql://127.0.0.1:1/unavailable?connectTimeout=1");
        var checker = new VerificarAcessoClienteUseCase(new JdbcIdentityTransaction(broken),
                alvo -> new IdentidadeAcessoCliente(UUID.randomUUID(), "os-service", alvo, CLOCK.instant().plusSeconds(60)),
                Set.of("os-service"), CLOCK);
        assertEquals(PERSISTENCIA, assertThrows(IdentityException.class,
                () -> checker.executar(UUID.randomUUID().toString())).motivo());
    }
}
