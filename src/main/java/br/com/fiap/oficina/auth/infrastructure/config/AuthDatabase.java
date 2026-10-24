package br.com.fiap.oficina.auth.infrastructure.config;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import java.util.Map;

public final class AuthDatabase {
    private AuthDatabase() {}

    public static HikariDataSource criar(Map<String, String> env) {
        String host = required(env, "AUTH_DB_HOST");
        String name = required(env, "AUTH_DB_NAME");
        String port = env.getOrDefault("AUTH_DB_PORT", "5432");
        String ssl = env.getOrDefault("AUTH_DB_SSLMODE", "verify-full");
        if (!host.matches("[a-zA-Z0-9.-]+") || !name.matches("[a-zA-Z0-9_]+")
                || !port.matches("[0-9]{1,5}") || Integer.parseInt(port) < 1 || Integer.parseInt(port) > 65535
                || !(ssl.equals("verify-full") || (ssl.equals("disable") && host.equals("127.0.0.1")
                && "local".equals(env.get("AUTH_ENVIRONMENT"))))) {
            throw new IllegalArgumentException("Configuracao AUTH_DB invalida");
        }
        HikariConfig config = new HikariConfig();
        config.setJdbcUrl("jdbc:postgresql://" + host + ":" + port + "/" + name);
        config.setUsername(required(env, "AUTH_DB_USER"));
        config.setPassword(required(env, "AUTH_DB_PASSWORD"));
        config.setMaximumPoolSize(2);
        config.setMinimumIdle(0);
        config.setConnectionTimeout(3000);
        config.setValidationTimeout(1000);
        config.setIdleTimeout(60000);
        config.setMaxLifetime(300000);
        config.setInitializationFailTimeout(-1);
        config.addDataSourceProperty("connectTimeout", "3");
        config.addDataSourceProperty("socketTimeout", "5");
        config.addDataSourceProperty("options", "-c statement_timeout=4000 -c lock_timeout=2000 -c idle_in_transaction_session_timeout=10000");
        config.addDataSourceProperty("sslmode", ssl);
        return new HikariDataSource(config);
    }

    private static String required(Map<String, String> env, String name) {
        String value = env.get(name);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Configuracao obrigatoria ausente: " + name);
        }
        return value;
    }
}

