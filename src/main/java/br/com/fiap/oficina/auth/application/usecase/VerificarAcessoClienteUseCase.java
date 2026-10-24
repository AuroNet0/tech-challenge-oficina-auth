package br.com.fiap.oficina.auth.application.usecase;

import br.com.fiap.oficina.auth.application.port.in.AcessoClienteView;
import br.com.fiap.oficina.auth.application.port.out.*;
import br.com.fiap.oficina.auth.domain.exception.IdentityException;
import java.time.Clock;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import static br.com.fiap.oficina.auth.domain.exception.IdentityException.Motivo.*;

public final class VerificarAcessoClienteUseCase {
    private final IdentityTransaction transacao;
    private final ClientAccessAuthentication autenticacao;
    private final Set<String> servicosPermitidos;
    private final Clock clock;

    public VerificarAcessoClienteUseCase(IdentityTransaction transacao, ClientAccessAuthentication autenticacao,
                                        Set<String> servicosPermitidos, Clock clock) {
        this.transacao = Objects.requireNonNull(transacao);
        this.autenticacao = Objects.requireNonNull(autenticacao);
        this.servicosPermitidos = Set.copyOf(servicosPermitidos);
        this.clock = Objects.requireNonNull(clock);
    }

    public AcessoClienteView executar(String clienteId) {
        UUID alvo;
        try {
            alvo = UUID.fromString(clienteId);
            if (!alvo.toString().equals(clienteId)) { throw new IllegalArgumentException(); }
        } catch (IllegalArgumentException | NullPointerException exception) {
            throw new IdentityException(INVALIDO);
        }
        var identidade = autenticacao.autenticar(alvo);
        exigirIdentidade(identidade, alvo);
        if (!servicosPermitidos.contains(identidade.servicoId())) {
            throw new IdentityException(NAO_AUTORIZADO);
        }
        return transacao.executar(repository -> {
            var usuario = repository.buscarPorId(identidade.usuarioId());
            exigirIdentidade(identidade, alvo);
            return new AcessoClienteView(usuario.filter(value -> value.id().equals(identidade.usuarioId()))
                    .map(value -> value.podeAcessarCliente(alvo)).orElse(false));
        });
    }

    private void exigirIdentidade(IdentidadeAcessoCliente identidade, UUID alvo) {
        if (identidade == null || !alvo.equals(identidade.clienteId())
                || !clock.instant().isBefore(identidade.validoAte())) {
            throw new IdentityException(CREDENCIAIS_INVALIDAS);
        }
    }
}
