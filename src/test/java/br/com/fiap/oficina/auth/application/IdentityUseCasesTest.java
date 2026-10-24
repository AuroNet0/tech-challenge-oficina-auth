package br.com.fiap.oficina.auth.application;

import br.com.fiap.oficina.auth.application.port.out.*;
import br.com.fiap.oficina.auth.application.usecase.*;
import br.com.fiap.oficina.auth.domain.enums.Papel;
import br.com.fiap.oficina.auth.domain.exception.IdentityException;
import br.com.fiap.oficina.auth.domain.model.Usuario;
import br.com.fiap.oficina.auth.infrastructure.security.Argon2idPasswordHasher;
import org.junit.jupiter.api.Test;
import java.time.Clock;
import java.util.*;
import java.util.function.Function;
import static br.com.fiap.oficina.auth.domain.exception.IdentityException.Motivo.*;
import static org.junit.jupiter.api.Assertions.*;

class IdentityUseCasesTest {
    private final Clock clock = Clock.systemUTC();
    private final MemoryStore store = new MemoryStore();
    private final ProvisioningAuthorization allowed = (operacao, usuario, cliente) -> {};
    private final ProvisioningAuthorization denied = (operacao, usuario, cliente) -> {
        throw new IdentityException(NAO_AUTORIZADO);
    };

    @Test
    void cicloDeVidaInternoSemHashNoDto() throws Exception {
        var cadastro = new CadastrarUsuarioUseCase(store, new Argon2idPasswordHasher(), allowed, clock);
        var view = cadastro.executar("Pessoa@example.test", "Pessoa ficticia", null, "senha-ficticia-segura".toCharArray());
        UUID id = view.id();
        assertTrue(view.papeis().isEmpty());
        assertFalse(view.toString().contains("$argon2"));
        var busca = new BuscarUsuarioUseCase(store, allowed);
        assertEquals(view, busca.porId(id));
        assertEquals(view, busca.porEmail(" PESSOA@example.test "));
        assertThrows(IdentityException.class, () -> busca.porId(UUID.randomUUID()));
        assertThrows(IdentityException.class, () -> busca.porEmail("ausente@example.test"));
        new AtribuirPapelUseCase(store, allowed, clock).executar(id, Papel.CLIENTE);
        new AtribuirPapelUseCase(store, allowed, clock).executar(id, Papel.MECANICO);
        UUID cliente = UUID.randomUUID();
        var vinculado = new VincularClienteUseCase(store, allowed, clock).executar(id, cliente);
        assertEquals(Set.of(cliente), vinculado.clientes());
        assertEquals(Set.of(Papel.CLIENTE, Papel.MECANICO), vinculado.papeis());
        assertThrows(IdentityException.class, () -> new VincularClienteUseCase(store, allowed, clock).executar(id, cliente));
        assertThrows(IdentityException.class, () -> new AtribuirPapelUseCase(store, allowed, clock).executar(id, Papel.CLIENTE));
        assertFalse(new DesativarUsuarioUseCase(store, allowed, clock).executar(id).ativo());
        assertThrows(IdentityException.class, () -> new AtribuirPapelUseCase(store, allowed, clock).executar(id, Papel.GERENTE));
        assertThrows(IdentityException.class, () -> cadastro.executar("pessoa@example.test", "Outro", null, "senha-ficticia-segura".toCharArray()));
    }

    @Test
    void negaProvisionamentoAntesDeConsultarOuPersistir() {
        UUID id = UUID.randomUUID();
        assertThrows(IdentityException.class, () -> new CadastrarUsuarioUseCase(store, new Argon2idPasswordHasher(), denied, clock)
                .executar("a@example.test", "a", null, "senha-ficticia-segura".toCharArray()));
        assertThrows(IdentityException.class, () -> new AtribuirPapelUseCase(store, denied, clock).executar(id, Papel.GERENTE));
        assertThrows(IdentityException.class, () -> new VincularClienteUseCase(store, denied, clock).executar(id, UUID.randomUUID()));
        assertThrows(IdentityException.class, () -> new DesativarUsuarioUseCase(store, denied, clock).executar(id));
        assertThrows(IdentityException.class, () -> new BuscarUsuarioUseCase(store, denied).porId(id));
        assertThrows(IdentityException.class, () -> new BuscarUsuarioUseCase(store, denied).porEmail("a@example.test"));
        assertEquals(0, store.chamadas);
    }

    @Test
    void rejeitaMutacoesDeIdentidadeAusente() {
        UUID id = UUID.randomUUID();
        assertThrows(IdentityException.class, () -> new AtribuirPapelUseCase(store, allowed, clock).executar(id, Papel.GERENTE));
        assertThrows(IdentityException.class, () -> new VincularClienteUseCase(store, allowed, clock).executar(id, UUID.randomUUID()));
        assertThrows(IdentityException.class, () -> new DesativarUsuarioUseCase(store, allowed, clock).executar(id));
    }

    private static class MemoryStore implements IdentityTransaction, UsuarioRepository {
        private final Map<UUID, Usuario> usuarios = new HashMap<>();
        private int chamadas;
        public <T> T executar(Function<UsuarioRepository, T> operation) {
            chamadas++;
            return operation.apply(this);
        }
        public Optional<Usuario> buscarPorId(UUID id) { return Optional.ofNullable(usuarios.get(id)); }
        public Optional<Usuario> buscarPorEmail(String email) {
            return usuarios.values().stream().filter(usuario -> usuario.email().equals(email)).findFirst();
        }
        public void inserir(Usuario usuario) {
            if (buscarPorEmail(usuario.email()).isPresent()) { throw new IdentityException(DUPLICADO); }
            usuarios.put(usuario.id(), usuario);
        }
        public void salvar(Usuario usuario) { usuarios.put(usuario.id(), usuario); }
    }
}

