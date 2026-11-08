package br.com.fiap.oficina.auth.application;

import br.com.fiap.oficina.auth.application.port.in.AcessoClienteView;
import br.com.fiap.oficina.auth.application.port.out.*;
import br.com.fiap.oficina.auth.application.usecase.VerificarAcessoClienteUseCase;
import br.com.fiap.oficina.auth.domain.enums.Papel;
import br.com.fiap.oficina.auth.domain.exception.IdentityException;
import br.com.fiap.oficina.auth.domain.model.Usuario;
import br.com.fiap.oficina.auth.support.AuthFixtures;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import static br.com.fiap.oficina.auth.domain.exception.IdentityException.Motivo.*;
import static br.com.fiap.oficina.auth.support.AuthFixtures.NOW;
import static org.junit.jupiter.api.Assertions.*;

class VerificarAcessoClienteUseCaseTest {
    private final AuthFixtures.MutableClock clock = new AuthFixtures.MutableClock(NOW);
    private final UUID cliente = UUID.randomUUID();
    private final Usuario usuario = Usuario.criar("pessoa@example.test", "Pessoa ficticia", null,
            AuthFixtures.oldHash(), NOW);
    private final AuthFixtures.Store store = new AuthFixtures.Store(usuario);

    private IdentidadeAcessoCliente identidade(UUID alvo) {
        return new IdentidadeAcessoCliente(usuario.id(), "os-service", alvo, NOW.plusSeconds(60));
    }

    private VerificarAcessoClienteUseCase useCase(ClientAccessAuthentication authentication) {
        return new VerificarAcessoClienteUseCase(store, authentication, Set.of("os-service"), clock);
    }

    private void vincular() {
        usuario.atribuir(Papel.CLIENTE, NOW);
        usuario.vincular(cliente, NOW);
    }

    @Test
    void autorizaSomenteVinculoDoUsuarioAutenticadoESemDadosPessoaisNaResposta() throws Exception {
        vincular();
        var resultado = useCase(this::identidade).executar(cliente.toString());
        assertTrue(resultado.autorizado());
        assertEquals("{\"autorizado\":true}", new ObjectMapper().writeValueAsString(resultado));
        assertArrayEquals(new String[]{"autorizado"}, java.util.Arrays.stream(AcessoClienteView.class.getRecordComponents())
                .map(java.lang.reflect.RecordComponent::getName).toArray(String[]::new));
    }

    @Test
    void negaUsuarioAusenteInativoSemPapelOuSemVinculoComMesmoResultado() {
        var checker = useCase(this::identidade);
        var negado = new AcessoClienteView(false);
        assertEquals(negado, checker.executar(cliente.toString()));
        usuario.atribuir(Papel.CLIENTE, NOW);
        assertEquals(negado, checker.executar(cliente.toString()));
        usuario.vincular(cliente, NOW);
        assertTrue(checker.executar(cliente.toString()).autorizado());
        usuario.desativar(NOW);
        assertEquals(negado, checker.executar(cliente.toString()));
        store.usuario = null;
        assertEquals(negado, checker.executar(cliente.toString()));
    }

    @Test
    void naoConcedePrivilegiosDeClienteAoGerente() {
        usuario.atribuir(Papel.GERENTE, NOW);
        assertFalse(useCase(this::identidade).executar(cliente.toString()).autorizado());
    }

    @Test
    void permiteMultiplosClientesSemRetornarListaDeVinculos() {
        vincular();
        UUID outroCliente = UUID.randomUUID();
        usuario.vincular(outroCliente, NOW);
        var checker = useCase(this::identidade);
        assertTrue(checker.executar(cliente.toString()).autorizado());
        assertTrue(checker.executar(outroCliente.toString()).autorizado());
        assertFalse(checker.executar(UUID.randomUUID().toString()).autorizado());
    }

    @Test
    void naoPermiteEscolherOutroUsuarioComBaseNoClienteAlvo() {
        vincular();
        UUID outroUsuario = UUID.randomUUID();
        var checker = useCase(alvo -> new IdentidadeAcessoCliente(outroUsuario, "os-service", alvo, NOW.plusSeconds(60)));
        assertFalse(checker.executar(cliente.toString()).autorizado());
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"", "invalido", "12345678909", "1-1-1-1-1", "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA",
            " 12345678-1234-1234-1234-123456789012"})
    void rejeitaUuidInvalidoAntesDeAutenticar(String alvo) {
        var checker = useCase(ignored -> { fail("Nao deve autenticar entrada invalida"); return null; });
        assertEquals(INVALIDO, assertThrows(IdentityException.class, () -> checker.executar(alvo)).motivo());
    }

    @Test
    void rejeitaContextoAusenteExpiradoOuDestinadoAOutroAlvoAntesDoBanco() {
        var chamadas = new AtomicInteger();
        IdentityTransaction transaction = contando(chamadas);
        for (ClientAccessAuthentication authentication : new ClientAccessAuthentication[]{
                alvo -> null,
                alvo -> new IdentidadeAcessoCliente(usuario.id(), "os-service", alvo, NOW),
                alvo -> identidade(UUID.randomUUID()),
                alvo -> { throw new IdentityException(CREDENCIAIS_INVALIDAS); }
        }) {
            var checker = new VerificarAcessoClienteUseCase(transaction, authentication, Set.of("os-service"), clock);
            assertEquals(CREDENCIAIS_INVALIDAS, assertThrows(IdentityException.class,
                    () -> checker.executar(cliente.toString())).motivo());
        }
        assertEquals(0, chamadas.get());
    }

    @Test
    void negaServicoNaoAutorizadoEAllowlistVaziaAntesDoBanco() {
        var chamadas = new AtomicInteger();
        for (Set<String> permitidos : Set.of(Set.<String>of(), Set.of("billing-service"))) {
            var checker = new VerificarAcessoClienteUseCase(contando(chamadas), this::identidade, permitidos, clock);
            assertEquals(NAO_AUTORIZADO, assertThrows(IdentityException.class,
                    () -> checker.executar(cliente.toString())).motivo());
        }
        assertEquals(0, chamadas.get());
    }

    @Test
    void naoUsaCachePositivoERevalidaValidadeDepoisDeEsperarTransacao() {
        vincular();
        var checker = useCase(this::identidade);
        assertTrue(checker.executar(cliente.toString()).autorizado());
        usuario.desativar(NOW);
        assertFalse(checker.executar(cliente.toString()).autorizado());
        IdentityTransaction delayed = new IdentityTransaction() {
            public <T> T executar(Function<UsuarioRepository, T> operation) {
                clock.set(NOW.plusSeconds(60));
                return store.executar(operation);
            }
        };
        clock.set(NOW);
        var waiting = new VerificarAcessoClienteUseCase(delayed, this::identidade, Set.of("os-service"), clock);
        assertEquals(CREDENCIAIS_INVALIDAS, assertThrows(IdentityException.class,
                () -> waiting.executar(cliente.toString())).motivo());
    }

    @Test
    void preservaFalhaDeInfraestruturaSemConverterEmDecisao() {
        for (IdentityException.Motivo motivo : Set.of(PERSISTENCIA, CONCORRENCIA)) {
            IdentityTransaction broken = new IdentityTransaction() {
                public <T> T executar(Function<UsuarioRepository, T> operation) { throw new IdentityException(motivo); }
            };
            var checker = new VerificarAcessoClienteUseCase(broken, this::identidade, Set.of("os-service"), clock);
            assertEquals(motivo, assertThrows(IdentityException.class, () -> checker.executar(cliente.toString())).motivo());
        }
        var unavailable = useCase(alvo -> { throw new IdentityException(PERSISTENCIA); });
        assertEquals(PERSISTENCIA, assertThrows(IdentityException.class,
                () -> unavailable.executar(cliente.toString())).motivo());
    }

    @Test
    void naoRetornaAutorizacaoQuandoCommitFalhaDepoisDaLeitura() {
        vincular();
        IdentityTransaction commitFailure = new IdentityTransaction() {
            public <T> T executar(Function<UsuarioRepository, T> operation) {
                operation.apply(store);
                throw new IdentityException(PERSISTENCIA);
            }
        };
        var checker = new VerificarAcessoClienteUseCase(commitFailure, this::identidade, Set.of("os-service"), clock);
        assertEquals(PERSISTENCIA, assertThrows(IdentityException.class,
                () -> checker.executar(cliente.toString())).motivo());
    }

    @Test
    void rejeitaIdentidadeIncompletaSemExporValores() {
        for (Runnable tentativa : new Runnable[]{
                () -> new IdentidadeAcessoCliente(null, "os-service", cliente, NOW),
                () -> new IdentidadeAcessoCliente(usuario.id(), null, cliente, NOW),
                () -> new IdentidadeAcessoCliente(usuario.id(), "servico com espacos", cliente, NOW),
                () -> new IdentidadeAcessoCliente(usuario.id(), "os-service", null, NOW),
                () -> new IdentidadeAcessoCliente(usuario.id(), "os-service", cliente, null)
        }) {
            assertEquals(CREDENCIAIS_INVALIDAS, assertThrows(IdentityException.class, tentativa::run).motivo());
        }
    }

    private IdentityTransaction contando(AtomicInteger chamadas) {
        return new IdentityTransaction() {
            public <T> T executar(Function<UsuarioRepository, T> operation) {
                chamadas.incrementAndGet();
                return store.executar(operation);
            }
        };
    }
}
