package br.com.fiap.oficina.auth.application.usecase;

import br.com.fiap.oficina.auth.application.port.in.AccessToken;
import br.com.fiap.oficina.auth.application.port.out.*;
import br.com.fiap.oficina.auth.domain.exception.IdentityException;
import br.com.fiap.oficina.auth.domain.model.Usuario;
import java.time.Clock;
import java.util.Arrays;
import java.util.UUID;
import static br.com.fiap.oficina.auth.domain.exception.IdentityException.Motivo.*;

public final class AutenticarUsuarioUseCase {
    private final IdentityTransaction transacao;
    private final PasswordHasher hasher;
    private final TokenIssuer issuer;
    private final Clock clock;
    private final String dummyHash;

    public AutenticarUsuarioUseCase(IdentityTransaction transacao, PasswordHasher hasher, TokenIssuer issuer, Clock clock) {
        this.transacao = transacao;
        this.hasher = hasher;
        this.issuer = issuer;
        this.clock = clock;
        char[] dummy = UUID.randomUUID().toString().toCharArray();
        try {
            this.dummyHash = hasher.hash(dummy);
        } finally {
            Arrays.fill(dummy, '\u0000');
        }
    }

    public AccessToken executar(String email, char[] senha) {
        String normalizado = validar(email, senha);
        return transacao.executar(repository -> {
            var usuario = repository.buscarPorEmail(normalizado);
            String hash = usuario.map(Usuario::passwordHash).orElse(dummyHash);
            boolean valida = hasher.verificar(senha, hash);
            if (usuario.isEmpty() || !valida || !usuario.get().ativo()) {
                throw new IdentityException(CREDENCIAIS_INVALIDAS);
            }
            Usuario ativo = usuario.get();
            if (hasher.precisaRehash(hash)) {
                String novo = hasher.hash(senha);
                if (!repository.atualizarHash(ativo.id(), hash, novo, clock.instant())) {
                    throw new IdentityException(CONCORRENCIA);
                }
            }
            return issuer.emitir(ativo.id(), ativo.papeis());
        });
    }

    public static String validar(String email, char[] senha) {
        if (email == null || email.length() > 320 || senha == null || senha.length < 12 || senha.length > 1024) {
            throw new IdentityException(INVALIDO);
        }
        return Usuario.normalizarEmail(email);
    }
}
