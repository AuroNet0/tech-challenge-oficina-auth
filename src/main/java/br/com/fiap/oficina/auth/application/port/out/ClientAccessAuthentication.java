package br.com.fiap.oficina.auth.application.port.out;

import java.util.UUID;

@FunctionalInterface
public interface ClientAccessAuthentication {
    IdentidadeAcessoCliente autenticar(UUID clienteId);
}
