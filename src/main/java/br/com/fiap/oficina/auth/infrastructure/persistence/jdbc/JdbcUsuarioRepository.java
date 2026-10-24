package br.com.fiap.oficina.auth.infrastructure.persistence.jdbc;

import br.com.fiap.oficina.auth.application.port.out.UsuarioRepository;
import br.com.fiap.oficina.auth.domain.enums.Papel;
import br.com.fiap.oficina.auth.domain.model.*;
import br.com.fiap.oficina.auth.domain.exception.IdentityException;
import java.sql.*;
import java.util.*;
import static br.com.fiap.oficina.auth.domain.exception.IdentityException.Motivo.*;

final class JdbcUsuarioRepository implements UsuarioRepository {
    private final Connection connection;
    private final Set<UUID> bloqueados = new HashSet<>();

    JdbcUsuarioRepository(Connection connection) {
        this.connection = connection;
    }

    @Override
    public Optional<Usuario> buscarPorId(UUID id) {
        return buscar("SELECT * FROM usuarios WHERE id = ? FOR UPDATE", id);
    }

    @Override
    public Optional<Usuario> buscarPorEmail(String email) {
        return buscar("SELECT * FROM usuarios WHERE email = ? FOR UPDATE", Usuario.normalizarEmail(email));
    }

    private Optional<Usuario> buscar(String sql, Object valor) {
        try (var statement = connection.prepareStatement(sql)) {
            statement.setObject(1, valor);
            try (var rows = statement.executeQuery()) {
                if (!rows.next()) {
                    return Optional.empty();
                }
                UUID id = rows.getObject("id", UUID.class);
                bloqueados.add(id);
                return Optional.of(new Usuario(id, rows.getString("email"), rows.getString("nome"),
                        rows.getString("cpf"), rows.getString("password_hash"), rows.getBoolean("ativo"),
                        rows.getTimestamp("criado_em").toInstant(), rows.getTimestamp("atualizado_em").toInstant(),
                        papeis(id), clientes(id)));
            }
        } catch (SQLException exception) {
            throw JdbcIdentityTransaction.traduzir(exception);
        }
    }

    private Set<Papel> papeis(UUID id) throws SQLException {
        Set<Papel> result = EnumSet.noneOf(Papel.class);
        try (var statement = connection.prepareStatement("SELECT papel FROM usuario_papeis WHERE usuario_id = ?")) {
            statement.setObject(1, id);
            try (var rows = statement.executeQuery()) {
                while (rows.next()) {
                    result.add(Papel.valueOf(rows.getString("papel")));
                }
            }
        }
        return result;
    }

    private List<UsuarioCliente> clientes(UUID id) throws SQLException {
        List<UsuarioCliente> result = new ArrayList<>();
        try (var statement = connection.prepareStatement("SELECT cliente_id, criado_em FROM usuario_clientes WHERE usuario_id = ?")) {
            statement.setObject(1, id);
            try (var rows = statement.executeQuery()) {
                while (rows.next()) {
                    result.add(new UsuarioCliente(id, rows.getObject("cliente_id", UUID.class),
                            rows.getTimestamp("criado_em").toInstant()));
                }
            }
        }
        return result;
    }

    @Override
    public void inserir(Usuario usuario) {
        try (var statement = connection.prepareStatement("""
                INSERT INTO usuarios (email, nome, cpf, password_hash, ativo, criado_em, atualizado_em, id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """)) {
            preencher(statement, usuario);
            statement.executeUpdate();
            associacoes(usuario);
        } catch (SQLException exception) {
            throw JdbcIdentityTransaction.traduzir(exception);
        }
    }

    @Override
    public void salvar(Usuario usuario) {
        if (!bloqueados.contains(usuario.id())) {
            throw new IdentityException(CONCORRENCIA);
        }
        try (var statement = connection.prepareStatement("""
                UPDATE usuarios SET email=?, nome=?, cpf=?, password_hash=?, ativo=?, criado_em=?, atualizado_em=? WHERE id=?
                """)) {
            preencher(statement, usuario);
            if (statement.executeUpdate() != 1) {
                throw new IdentityException(NAO_ENCONTRADO);
            }
            associacoes(usuario);
        } catch (SQLException exception) {
            throw JdbcIdentityTransaction.traduzir(exception);
        }
    }

    private void preencher(PreparedStatement statement, Usuario usuario) throws SQLException {
        statement.setString(1, usuario.email());
        statement.setString(2, usuario.nome());
        statement.setString(3, usuario.cpf());
        statement.setString(4, usuario.passwordHash());
        statement.setBoolean(5, usuario.ativo());
        statement.setTimestamp(6, Timestamp.from(usuario.criadoEm()));
        statement.setTimestamp(7, Timestamp.from(usuario.atualizadoEm()));
        statement.setObject(8, usuario.id());
    }

    @Override
    public boolean atualizarHash(UUID id, String anterior, String novo, java.time.Instant agora) {
        if (!bloqueados.contains(id)) {
            throw new IdentityException(CONCORRENCIA);
        }
        try (var statement = connection.prepareStatement("UPDATE usuarios SET password_hash=?, atualizado_em=GREATEST(atualizado_em, ?) WHERE id=? AND password_hash=? AND ativo")) {
            statement.setString(1, novo);
            statement.setTimestamp(2, Timestamp.from(agora));
            statement.setObject(3, id);
            statement.setString(4, anterior);
            return statement.executeUpdate() == 1;
        } catch (SQLException exception) {
            throw JdbcIdentityTransaction.traduzir(exception);
        }
    }

    private void associacoes(Usuario usuario) throws SQLException {
        try (var statement = connection.prepareStatement("INSERT INTO usuario_papeis (usuario_id, papel) VALUES (?, ?) ON CONFLICT DO NOTHING")) {
            for (Papel papel : usuario.papeis()) {
                statement.setObject(1, usuario.id());
                statement.setString(2, papel.name());
                statement.addBatch();
            }
            statement.executeBatch();
        }
        try (var statement = connection.prepareStatement("INSERT INTO usuario_clientes (usuario_id, cliente_id, criado_em) VALUES (?, ?, ?) ON CONFLICT DO NOTHING")) {
            for (UsuarioCliente vinculo : usuario.clientes()) {
                statement.setObject(1, usuario.id());
                statement.setObject(2, vinculo.clienteId());
                statement.setTimestamp(3, Timestamp.from(vinculo.criadoEm()));
                statement.addBatch();
            }
            statement.executeBatch();
        }
    }
}
