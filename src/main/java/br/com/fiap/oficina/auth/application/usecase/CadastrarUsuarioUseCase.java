package br.com.fiap.oficina.auth.application.usecase;

import br.com.fiap.oficina.auth.application.port.in.UsuarioView;
import br.com.fiap.oficina.auth.application.port.out.*;
import br.com.fiap.oficina.auth.domain.model.Usuario;
import java.time.Clock;
import static br.com.fiap.oficina.auth.application.port.out.ProvisioningAuthorization.Operacao.CADASTRAR;

public record CadastrarUsuarioUseCase(IdentityTransaction transacao, PasswordHasher hasher,
                                     ProvisioningAuthorization autorizacao, Clock clock) {
    public UsuarioView executar(String email, String nome, String cpf, char[] senha) {
        autorizacao.exigir(CADASTRAR, null, null);
        String normalizado = Usuario.normalizarEmail(email);
        String hash = hasher.hash(senha);
        Usuario usuario = Usuario.criar(normalizado, nome, cpf, hash, clock.instant());
        return transacao.executar(repository -> {
            repository.inserir(usuario);
            return UsuarioView.de(usuario);
        });
    }
}

