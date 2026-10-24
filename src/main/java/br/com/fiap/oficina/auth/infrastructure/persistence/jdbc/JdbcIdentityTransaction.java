package br.com.fiap.oficina.auth.infrastructure.persistence.jdbc;

import br.com.fiap.oficina.auth.application.port.out.*;
import br.com.fiap.oficina.auth.domain.exception.IdentityException;
import javax.sql.DataSource;
import java.sql.SQLException;
import java.util.function.Function;
import static br.com.fiap.oficina.auth.domain.exception.IdentityException.Motivo.*;

public final class JdbcIdentityTransaction implements IdentityTransaction {
    private final DataSource datasource;

    public JdbcIdentityTransaction(DataSource datasource) {
        this.datasource = datasource;
    }

    @Override
    public <T> T executar(Function<UsuarioRepository, T> operacao) {
        try (var connection = datasource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                T result = operacao.apply(new JdbcUsuarioRepository(connection));
                connection.commit();
                return result;
            } catch (RuntimeException | SQLException exception) {
                try {
                    connection.rollback();
                } catch (SQLException rollbackException) {
                    throw new IdentityException(PERSISTENCIA);
                }
                if (exception instanceof IdentityException identityException) {
                    throw identityException;
                }
                if (exception instanceof SQLException sqlException) {
                    throw traduzir(sqlException);
                }
                throw new IdentityException(PERSISTENCIA);
            }
        } catch (SQLException exception) {
            throw traduzir(exception);
        }
    }

    static IdentityException traduzir(SQLException exception) {
        return new IdentityException(switch (exception.getSQLState() == null ? "" : exception.getSQLState()) {
            case "23505" -> DUPLICADO;
            case "40001", "40P01", "55P03" -> CONCORRENCIA;
            default -> PERSISTENCIA;
        });
    }
}
