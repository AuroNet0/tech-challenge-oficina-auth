package br.com.fiap.oficina.auth.application.usecase;

import br.com.fiap.oficina.auth.application.port.in.UsuarioView;
import br.com.fiap.oficina.auth.application.port.out.*;
import br.com.fiap.oficina.auth.domain.enums.Papel;
import br.com.fiap.oficina.auth.domain.exception.IdentityException;
import java.time.Clock;
import java.util.UUID;
import static br.com.fiap.oficina.auth.application.port.out.ProvisioningAuthorization.Operacao.VINCULAR_CLIENTE;
import static br.com.fiap.oficina.auth.domain.exception.IdentityException.Motivo.NAO_ENCONTRADO;

public record VincularClienteUseCase(IdentityTransaction transacao, ProvisioningAuthorization autorizacao, Clock clock) {
    public UsuarioView executar(UUID id, UUID clienteId) {
        autorizacao.exigir(VINCULAR_CLIENTE, id, clienteId);
        return transacao.executar(repository -> {
            var usuario = repository.buscarPorId(id).orElseThrow(() -> new IdentityException(NAO_ENCONTRADO));
            usuario.vincular(clienteId, clock.instant());
            repository.salvar(usuario);
            return UsuarioView.de(usuario);
        });
    }
}

