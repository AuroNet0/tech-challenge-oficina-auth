package br.com.fiap.oficina.auth.application.port.out;

import br.com.fiap.oficina.auth.domain.model.Usuario;
import java.util.Optional;
import java.util.UUID;

public interface UsuarioRepository {
    Optional<Usuario> buscarPorId(UUID id);
    Optional<Usuario> buscarPorEmail(String email);
    void inserir(Usuario usuario);
    void salvar(Usuario usuario);
    boolean atualizarHash(UUID id, String anterior, String novo, java.time.Instant agora);
}
