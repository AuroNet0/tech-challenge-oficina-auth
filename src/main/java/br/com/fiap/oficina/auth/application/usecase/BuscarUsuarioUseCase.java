package br.com.fiap.oficina.auth.application.usecase;

import br.com.fiap.oficina.auth.application.port.in.UsuarioView;
import br.com.fiap.oficina.auth.application.port.out.*;
import br.com.fiap.oficina.auth.domain.exception.IdentityException;
import br.com.fiap.oficina.auth.domain.model.Usuario;
import java.util.UUID;
import static br.com.fiap.oficina.auth.application.port.out.ProvisioningAuthorization.Operacao.BUSCAR;
import static br.com.fiap.oficina.auth.domain.exception.IdentityException.Motivo.NAO_ENCONTRADO;

public record BuscarUsuarioUseCase(IdentityTransaction transacao, ProvisioningAuthorization autorizacao) {
    public UsuarioView porId(UUID id) {
        autorizacao.exigir(BUSCAR, id, null);
        return transacao.executar(repository -> UsuarioView.de(repository.buscarPorId(id)
                .orElseThrow(() -> new IdentityException(NAO_ENCONTRADO))));
    }

    public UsuarioView porEmail(String email) {
        autorizacao.exigir(BUSCAR, null, null);
        return transacao.executar(repository -> UsuarioView.de(repository.buscarPorEmail(Usuario.normalizarEmail(email))
                .orElseThrow(() -> new IdentityException(NAO_ENCONTRADO))));
    }
}

