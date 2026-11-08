package br.com.fiap.oficina.auth.infrastructure.config;

import org.flywaydb.core.Flyway;

public final class MigrateIdentity {
    private MigrateIdentity() {}

    public static void main(String[] args) {
        try (var datasource = AuthDatabase.criar(System.getenv())) {
            var flyway = Flyway.configure().dataSource(datasource).locations("classpath:db/migration")
                    .cleanDisabled(true).load();
            flyway.migrate();
            flyway.validate();
        }
    }
}

