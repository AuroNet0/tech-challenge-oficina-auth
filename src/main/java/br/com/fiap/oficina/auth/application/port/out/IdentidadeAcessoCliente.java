package br.com.fiap.oficina.auth.application.port.out;

import br.com.fiap.oficina.auth.domain.exception.IdentityException;
import java.time.Instant;
import java.util.UUID;
import static br.com.fiap.oficina.auth.domain.exception.IdentityException.Motivo.CREDENCIAIS_INVALIDAS;

public record IdentidadeAcessoCliente(UUID usuarioId, String servicoId, UUID clienteId, Instant validoAte) {
    public IdentidadeAcessoCliente {
        if (usuarioId == null || servicoId == null || !servicoId.matches("[A-Za-z0-9:/_.-]{1,200}")
                || clienteId == null || validoAte == null) {
            throw new IdentityException(CREDENCIAIS_INVALIDAS);
        }
    }
}
