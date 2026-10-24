package br.com.fiap.oficina.auth.application.usecase;

import br.com.fiap.oficina.auth.application.port.in.UsuarioView;
import br.com.fiap.oficina.auth.application.port.out.*;
import br.com.fiap.oficina.auth.domain.enums.Papel;
import br.com.fiap.oficina.auth.domain.exception.IdentityException;
import java.time.Clock;
import java.util.UUID;
import static br.com.fiap.oficina.auth.application.port.out.ProvisioningAuthorization.Operacao.ATRIBUIR_PAPEL;
import static br.com.fiap.oficina.auth.domain.exception.IdentityException.Motivo.NAO_ENCONTRADO;

public record AtribuirPapelUseCase(IdentityTransaction transacao, ProvisioningAuthorization autorizacao, Clock clock) {
    public UsuarioView executar(UUID id, Papel papel) {
        autorizacao.exigir(ATRIBUIR_PAPEL, id, null);
        return transacao.executar(repository -> {
            var usuario = repository.buscarPorId(id).orElseThrow(() -> new IdentityException(NAO_ENCONTRADO));
            usuario.atribuir(papel, clock.instant());
            repository.salvar(usuario);
            return UsuarioView.de(usuario);
        });
    }
}

