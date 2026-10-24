package br.com.fiap.oficina.auth.application.port.in;

import br.com.fiap.oficina.auth.domain.enums.Papel;
import br.com.fiap.oficina.auth.domain.model.Usuario;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

public record UsuarioView(UUID id, String email, String nome, boolean ativo,
                          Set<Papel> papeis, Set<UUID> clientes) {
    public static UsuarioView de(Usuario usuario) {
        return new UsuarioView(usuario.id(), usuario.email(), usuario.nome(), usuario.ativo(),
                usuario.papeis(), usuario.clientes().stream().map(vinculo -> vinculo.clienteId()).collect(Collectors.toUnmodifiableSet()));
    }
}

