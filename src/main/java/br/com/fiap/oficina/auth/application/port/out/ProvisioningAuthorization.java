package br.com.fiap.oficina.auth.application.port.out;

import java.util.UUID;

@FunctionalInterface
public interface ProvisioningAuthorization {
    enum Operacao { CADASTRAR, BUSCAR, ATRIBUIR_PAPEL, VINCULAR_CLIENTE, DESATIVAR }
    void exigir(Operacao operacao, UUID usuarioId, UUID clienteId);
}

