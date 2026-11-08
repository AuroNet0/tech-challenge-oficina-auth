package br.com.fiap.oficina.auth.domain.model;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public record UsuarioCliente(UUID usuarioId, UUID clienteId, Instant criadoEm) {
    public UsuarioCliente {
        Objects.requireNonNull(usuarioId);
        Objects.requireNonNull(clienteId);
        Objects.requireNonNull(criadoEm);
    }
}

