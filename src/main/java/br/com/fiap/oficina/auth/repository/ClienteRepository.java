package br.com.fiap.oficina.auth.repository;

import br.com.fiap.oficina.auth.model.ClienteAuth;

import java.util.Optional;

public interface ClienteRepository {

    Optional<ClienteAuth> findByCpf(String cpf);
}
