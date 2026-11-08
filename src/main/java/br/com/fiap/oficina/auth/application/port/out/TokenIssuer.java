package br.com.fiap.oficina.auth.application.port.out;

import br.com.fiap.oficina.auth.application.port.in.AccessToken;
import br.com.fiap.oficina.auth.domain.enums.Papel;
import java.util.Set;
import java.util.UUID;

@FunctionalInterface
public interface TokenIssuer {
    AccessToken emitir(UUID usuarioId, Set<Papel> papeis);
}
