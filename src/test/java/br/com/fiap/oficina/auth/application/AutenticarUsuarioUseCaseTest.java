package br.com.fiap.oficina.auth.application;

import br.com.fiap.oficina.auth.application.usecase.AutenticarUsuarioUseCase;
import br.com.fiap.oficina.auth.domain.model.Usuario;
import br.com.fiap.oficina.auth.domain.enums.Papel;
import br.com.fiap.oficina.auth.domain.exception.IdentityException;
import br.com.fiap.oficina.auth.infrastructure.security.*;
import br.com.fiap.oficina.auth.support.AuthFixtures;
import org.junit.jupiter.api.Test;
import java.time.*;
import java.util.*;
import static br.com.fiap.oficina.auth.support.AuthFixtures.*;
import static br.com.fiap.oficina.auth.domain.exception.IdentityException.Motivo.*;
import static org.junit.jupiter.api.Assertions.*;

class AutenticarUsuarioUseCaseTest {
    private final Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
    private final Argon2idPasswordHasher hasher = new Argon2idPasswordHasher();
    private final String hash = hasher.hash(SENHA.toCharArray());

    private AutenticarUsuarioUseCase login(AuthFixtures.Store store) {
        return new AutenticarUsuarioUseCase(store, hasher,
                new Rs256TokenIssuer(provider(clock), clock, ISSUER, AUDIENCE, 900), clock);
    }

    @Test
    void normalizaEmailEAutenticaSemPapeisOuComMultiplos() {
        var usuario = Usuario.criar("pessoa@example.test", "Ficticio", null, hash, NOW);
        var usecase = login(new Store(usuario));
        var first = usecase.executar(" PESSOA@EXAMPLE.TEST ", SENHA.toCharArray());
        assertEquals("Bearer", first.tokenType());
        assertEquals(900, first.expiresIn());
        assertFalse(first.toString().contains(first.accessToken()));
        usuario.atribuir(Papel.CLIENTE, NOW);
        usuario.atribuir(Papel.MECANICO, NOW);
        assertNotEquals(first.accessToken(), usecase.executar(usuario.email(), SENHA.toCharArray()).accessToken());
    }

    @Test
    void emailAusenteSenhaIncorretaEInativoTemMesmoErro() {
        var usuario = Usuario.criar("pessoa@example.test", "Ficticio", null, hash, NOW);
        var usecase = login(new Store(usuario));
        var missing = assertThrows(IdentityException.class, () -> usecase.executar("ausente@example.test", SENHA.toCharArray()));
        var wrong = assertThrows(IdentityException.class, () -> usecase.executar(usuario.email(), "outra-senha-ficticia".toCharArray()));
        usuario.desativar(NOW);
        var inactive = assertThrows(IdentityException.class, () -> usecase.executar(usuario.email(), SENHA.toCharArray()));
        assertEquals(CREDENCIAIS_INVALIDAS, missing.motivo());
        assertEquals(missing.getMessage(), wrong.getMessage());
        assertEquals(missing.getMessage(), inactive.getMessage());
    }

    @Test
    void limitaEntradaAntesDoBanco() {
        var store = new Store(null);
        var usecase = login(store);
        for (String email : new String[]{null, "", "a", "a".repeat(321)}) {
            assertThrows(IdentityException.class, () -> usecase.executar(email, SENHA.toCharArray()));
        }
        for (char[] password : new char[][]{null, new char[0], new char[11], new char[1025]}) {
            assertThrows(IdentityException.class, () -> usecase.executar("a@example.test", password));
        }
        assertEquals(0, store.reads);
    }

    @Test
    void rehashSeguroESemEmissaoSeComparacaoConcorrenteFalhar() {
        var usuario = Usuario.criar("pessoa@example.test", "Ficticio", null, oldHash(), NOW);
        var store = new Store(usuario);
        var usecase = login(store);
        usecase.executar(usuario.email(), SENHA.toCharArray());
        assertTrue(hasher.verificar(SENHA.toCharArray(), store.rehashed));
        assertFalse(hasher.precisaRehash(store.rehashed));
        store.updateSuccess = false;
        assertEquals(CONCORRENCIA, assertThrows(IdentityException.class,
                () -> usecase.executar(usuario.email(), SENHA.toCharArray())).motivo());
    }

    @Test
    void falhasDeBancoEChaveNaoEmitemToken() {
        var usuario = Usuario.criar("pessoa@example.test", "Ficticio", null, hash, NOW);
        var store = new Store(usuario);
        var usecase = new AutenticarUsuarioUseCase(store, hasher, (id, roles) -> {
            throw new IdentityException(PERSISTENCIA);
        }, clock);
        assertEquals(PERSISTENCIA, assertThrows(IdentityException.class,
                () -> usecase.executar(usuario.email(), SENHA.toCharArray())).motivo());
        var broken = new AutenticarUsuarioUseCase(new br.com.fiap.oficina.auth.application.port.out.IdentityTransaction() {
            public <T> T executar(java.util.function.Function<br.com.fiap.oficina.auth.application.port.out.UsuarioRepository, T> callback) {
                throw new IdentityException(PERSISTENCIA);
            }
        }, hasher, (id, roles) -> { fail(); return null; }, clock);
        assertThrows(IdentityException.class, () -> broken.executar(usuario.email(), SENHA.toCharArray()));
    }
}
