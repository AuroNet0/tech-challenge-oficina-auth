package br.com.fiap.oficina.auth.infrastructure.persistence.jdbc;

import br.com.fiap.oficina.auth.application.port.out.LoginRateLimiter;
import br.com.fiap.oficina.auth.domain.exception.IdentityException;
import javax.sql.DataSource;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import static br.com.fiap.oficina.auth.domain.exception.IdentityException.Motivo.*;

public final class JdbcLoginRateLimiter implements LoginRateLimiter {
    private final DataSource datasource;
    public JdbcLoginRateLimiter(DataSource datasource) { this.datasource = datasource; }

    @Override
    public void exigir(String sourceIp, String email) {
        if (sourceIp == null || !sourceIp.matches("[0-9a-fA-F:.]{3,64}")) {
            throw new IdentityException(INVALIDO);
        }
        var limits = new TreeMap<>(Map.of(digest("global"), 300, digest("ip:" + sourceIp), 20, digest("email:" + email), 10));
        try (var connection = datasource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                for (var entry : limits.entrySet()) {
                    try (var statement = connection.prepareStatement("""
                            INSERT INTO login_tentativas (chave, janela, tentativas)
                            VALUES (?, date_trunc('minute', CURRENT_TIMESTAMP), 1)
                            ON CONFLICT (chave, janela) DO UPDATE SET tentativas = login_tentativas.tentativas + 1
                            WHERE login_tentativas.tentativas < ?
                            RETURNING tentativas
                            """)) {
                        statement.setString(1, entry.getKey());
                        statement.setInt(2, entry.getValue());
                        try (var result = statement.executeQuery()) {
                            if (!result.next()) { throw new IdentityException(LIMITE_EXCEDIDO); }
                        }
                    }
                }
                connection.commit();
            } catch (Exception exception) {
                connection.rollback();
                if (exception instanceof IdentityException identityException) { throw identityException; }
                throw new IdentityException(PERSISTENCIA);
            }
        } catch (java.sql.SQLException exception) {
            throw new IdentityException(PERSISTENCIA);
        }
    }

    private String digest(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (java.security.NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 indisponivel");
        }
    }
}
