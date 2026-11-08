package br.com.fiap.oficina.auth.application.port.out;

import java.util.function.Function;

public interface IdentityTransaction {
    <T> T executar(Function<UsuarioRepository, T> operacao);
}

