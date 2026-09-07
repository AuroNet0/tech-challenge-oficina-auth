package br.com.fiap.oficina.auth.repository;

import br.com.fiap.oficina.auth.model.ClienteAuth;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Optional;

public class JdbcClienteRepository implements ClienteRepository {

    private static final String DEFAULT_DB_PORT = "5432";
    private static final String FIND_BY_CPF_SQL = """
            SELECT id, nome, cpf_cnpj, ativo
            FROM clientes
            WHERE regexp_replace(cpf_cnpj, '[^0-9]', '', 'g') = ?
            LIMIT 1
            """;

    @Override
    public Optional<ClienteAuth> findByCpf(String cpf) {
        String normalizedCpf = normalizeCpf(cpf);

        try (Connection connection = createConnection();
             PreparedStatement statement = connection.prepareStatement(FIND_BY_CPF_SQL)) {

            statement.setString(1, normalizedCpf);

            try (ResultSet resultSet = statement.executeQuery()) {
                if (!resultSet.next()) {
                    return Optional.empty();
                }

                return Optional.of(new ClienteAuth(
                        resultSet.getLong("id"),
                        resultSet.getString("nome"),
                        resultSet.getString("cpf_cnpj"),
                        resultSet.getBoolean("ativo")
                ));
            }
        } catch (SQLException exception) {
            throw new DatabaseException("Erro ao consultar cliente no banco de dados.", exception);
        }
    }

    private Connection createConnection() throws SQLException {
        String host = getRequiredEnv("DB_HOST");
        String port = getEnvOrDefault("DB_PORT", DEFAULT_DB_PORT);
        String database = getRequiredEnv("DB_NAME");
        String user = getRequiredEnv("DB_USER");
        String password = getRequiredEnv("DB_PASSWORD");
        String jdbcUrl = "jdbc:postgresql://" + host + ":" + port + "/" + database;

        return DriverManager.getConnection(jdbcUrl, user, password);
    }

    private String getRequiredEnv(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new DatabaseException("Variavel de ambiente obrigatoria nao configurada: " + name, null);
        }

        return value;
    }

    private String getEnvOrDefault(String name, String defaultValue) {
        String value = System.getenv(name);
        return value == null || value.isBlank() ? defaultValue : value;
    }

    private String normalizeCpf(String cpf) {
        if (cpf == null) {
            return "";
        }

        return cpf.replaceAll("\\D", "");
    }
}
