package br.com.fiap.oficina.auth.infrastructure.config;

import org.junit.jupiter.api.Test;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class AuthDatabaseTest {
    private Map<String, String> env() {
        return new HashMap<>(Map.of("AUTH_DB_HOST", "identity.internal", "AUTH_DB_NAME", "oficina_auth",
                "AUTH_DB_USER", "auth_test", "AUTH_DB_PASSWORD", "senha-apenas-fixture"));
    }

    @Test
    void configuracaoIndependenteComPoolLimitadoETls() {
        try (var datasource = AuthDatabase.criar(env())) {
            assertEquals(2, datasource.getMaximumPoolSize());
            assertEquals(0, datasource.getMinimumIdle());
            assertEquals(3000, datasource.getConnectionTimeout());
            assertEquals("verify-full", datasource.getDataSourceProperties().getProperty("sslmode"));
            assertEquals("jdbc:postgresql://identity.internal:5432/oficina_auth", datasource.getJdbcUrl());
            assertEquals("3", datasource.getDataSourceProperties().getProperty("connectTimeout"));
        }
        var local = env();
        local.putAll(Map.of("AUTH_DB_HOST", "127.0.0.1", "AUTH_ENVIRONMENT", "local", "AUTH_DB_SSLMODE", "disable"));
        try (var datasource = AuthDatabase.criar(local)) {
            assertEquals("disable", datasource.getDataSourceProperties().getProperty("sslmode"));
        }
    }

    @Test
    void recusaConfiguracaoAusenteInjecaoOuTlsDesativadoRemotamente() {
        assertThrows(IllegalArgumentException.class, () -> AuthDatabase.criar(Map.of("DB_HOST", "os.internal")));
        for (String key : List.of("AUTH_DB_HOST", "AUTH_DB_NAME", "AUTH_DB_USER", "AUTH_DB_PASSWORD")) {
            var invalid = env();
            invalid.put(key, " ");
            assertThrows(IllegalArgumentException.class, () -> AuthDatabase.criar(invalid));
        }
        for (var entry : Map.of("AUTH_DB_HOST", "host/?x=1", "AUTH_DB_NAME", "auth?sslmode=disable",
                "AUTH_DB_PORT", "65536", "AUTH_DB_SSLMODE", "disable").entrySet()) {
            var invalid = env();
            invalid.put(entry.getKey(), entry.getValue());
            assertThrows(IllegalArgumentException.class, () -> AuthDatabase.criar(invalid));
        }
        for (String port : List.of("0", "-1", "abc", "123456")) {
            var invalid = env();
            invalid.put("AUTH_DB_PORT", port);
            assertThrows(IllegalArgumentException.class, () -> AuthDatabase.criar(invalid));
        }
    }
}

