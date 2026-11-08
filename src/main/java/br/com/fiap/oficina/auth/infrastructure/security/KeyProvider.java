package br.com.fiap.oficina.auth.infrastructure.security;

import java.util.List;

public interface KeyProvider {
    SigningKey ativa();
    List<SigningKey> publicas();
    void atualizar();
}
