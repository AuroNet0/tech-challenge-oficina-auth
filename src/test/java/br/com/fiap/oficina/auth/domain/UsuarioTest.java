package br.com.fiap.oficina.auth.domain;

import br.com.fiap.oficina.auth.domain.model.*;
import br.com.fiap.oficina.auth.domain.enums.Papel;
import br.com.fiap.oficina.auth.domain.exception.IdentityException;
import org.junit.jupiter.api.Test;
import java.time.Instant;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class UsuarioTest {
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");
    private static final String HASH = "$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    private Usuario criar() {
        return Usuario.criar(" Pessoa+teste@EXAMPLE.test ", " Pessoa ficticia ", "123.456.789-09", HASH, NOW);
    }

    @Test
    void criaIdentidadeSemPrivilegiosEProtegeDados() {
        var usuario = criar();
        assertNotNull(usuario.id());
        assertEquals("pessoa+teste@example.test", usuario.email());
        assertEquals("Pessoa ficticia", usuario.nome());
        assertEquals("12345678909", usuario.cpf());
        assertEquals(NOW, usuario.criadoEm());
        assertEquals(NOW, usuario.atualizadoEm());
        assertEquals(HASH, usuario.passwordHash());
        assertTrue(usuario.ativo());
        assertTrue(usuario.papeis().isEmpty());
        assertFalse(usuario.possuiPrivilegio(Papel.GERENTE));
        assertFalse(usuario.podeAcessarCliente(UUID.randomUUID()));
        assertFalse(usuario.toString().contains(HASH));
        assertFalse(usuario.toString().contains(usuario.cpf()));
        assertEquals("nome.sobrenome@example.test", Usuario.normalizarEmail("Nome.Sobrenome@example.test"));
        assertNotEquals(Usuario.normalizarEmail("a.b@example.test"), Usuario.normalizarEmail("ab@example.test"));
        assertNull(Usuario.normalizarCpf(null));
    }

    @Test
    void rejeitaDadosInvalidos() {
        for (String email : Arrays.asList(null, "", "a", "a@", "@a.test", "a b@example.test",
                "a..b@example.test", "a@-a.test", "é@example.test", "a".repeat(255) + "@example.test")) {
            assertThrows(IdentityException.class, () -> Usuario.normalizarEmail(email));
        }
        for (String cpf : List.of("", "123", "abcdefghijk", "abc12345678909", "123456789090")) {
            assertThrows(IdentityException.class, () -> Usuario.normalizarCpf(cpf));
        }
        assertThrows(IdentityException.class, () -> Usuario.criar("a@example.test", "", null, HASH, NOW));
        assertThrows(IdentityException.class, () -> Usuario.criar("a@example.test", "a", null, "texto puro", NOW));
        assertThrows(IdentityException.class, () -> new Usuario(UUID.randomUUID(), "a@example.test", "a",
                null, HASH, true, NOW, NOW.minusSeconds(1), Set.of(), List.of()));
    }

    @Test
    void papeisMultiplosDuplicadosInvalidosEImutabilidade() {
        var usuario = criar();
        for (Papel papel : Papel.values()) {
            usuario.atribuir(papel, NOW.plusSeconds(1));
        }
        assertEquals(Set.of(Papel.values()), usuario.papeis());
        assertTrue(usuario.possuiPrivilegio(Papel.GERENTE));
        assertThrows(IdentityException.class, () -> usuario.atribuir(Papel.CLIENTE, NOW));
        assertThrows(IdentityException.class, () -> usuario.atribuir(null, NOW.plusSeconds(1)));
        assertThrows(IllegalArgumentException.class, () -> Papel.valueOf("ROOT"));
        assertThrows(UnsupportedOperationException.class, () -> usuario.papeis().clear());
    }

    @Test
    void vinculosExigemPapelEImpedemAcessoAOutrosClientes() {
        var usuario = criar();
        UUID cliente = UUID.randomUUID();
        assertThrows(IdentityException.class, () -> usuario.vincular(cliente, NOW));
        usuario.atribuir(Papel.CLIENTE, NOW);
        usuario.vincular(cliente, NOW);
        assertTrue(usuario.podeAcessarCliente(cliente));
        assertFalse(usuario.podeAcessarCliente(UUID.randomUUID()));
        assertThrows(IdentityException.class, () -> usuario.vincular(cliente, NOW));
        assertEquals(1, usuario.clientes().size());
        assertThrows(UnsupportedOperationException.class, () -> usuario.clientes().clear());
        usuario.desativar(NOW.plusSeconds(2));
        assertFalse(usuario.podeAcessarCliente(cliente));
        assertFalse(usuario.possuiPrivilegio(Papel.CLIENTE));
        assertThrows(IdentityException.class, usuario::exigirAtivo);
        assertThrows(IdentityException.class, () -> usuario.atribuir(Papel.GERENTE, NOW));
        assertThrows(IdentityException.class, () -> usuario.vincular(UUID.randomUUID(), NOW));
    }

    @Test
    void mutacaoRejeitaRelogioAnteriorOuAusenteSemAlterarEstado() {
        var usuario = criar();
        assertThrows(IdentityException.class, () -> usuario.atribuir(Papel.CLIENTE, NOW.minusSeconds(1)));
        assertThrows(IdentityException.class, () -> usuario.desativar(null));
        assertThrows(IdentityException.class, () -> usuario.vincular(UUID.randomUUID(), NOW.minusSeconds(1)));
        assertTrue(usuario.ativo());
        assertTrue(usuario.papeis().isEmpty());
        assertTrue(usuario.clientes().isEmpty());
    }

    @Test
    void reconstituicaoConfereDonoPapelEDuplicidade() {
        UUID id = UUID.randomUUID();
        var vinculo = new UsuarioCliente(id, UUID.randomUUID(), NOW);
        assertEquals(id, vinculo.usuarioId());
        assertEquals(NOW, vinculo.criadoEm());
        assertThrows(IdentityException.class, () -> new Usuario(id, "a@example.test", "a", null, HASH,
                true, NOW, NOW, Set.of(), List.of(vinculo)));
        assertThrows(IdentityException.class, () -> new Usuario(UUID.randomUUID(), "a@example.test", "a",
                null, HASH, true, NOW, NOW, Set.of(Papel.CLIENTE), List.of(vinculo)));
        assertThrows(IdentityException.class, () -> new Usuario(id, "a@example.test", "a", null, HASH,
                true, NOW, NOW, Set.of(Papel.CLIENTE), List.of(vinculo, vinculo)));
        var restored = new Usuario(id, "a@example.test", "a", null, HASH, true, NOW, NOW,
                Set.of(Papel.CLIENTE), List.of(vinculo));
        assertTrue(restored.podeAcessarCliente(vinculo.clienteId()));
    }
}
