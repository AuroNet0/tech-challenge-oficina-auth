package br.com.fiap.oficina.auth.infrastructure.config;

import br.com.fiap.oficina.auth.application.usecase.AutenticarUsuarioUseCase;
import br.com.fiap.oficina.auth.infrastructure.persistence.jdbc.*;
import br.com.fiap.oficina.auth.infrastructure.security.*;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import java.time.*;
import java.util.Map;
import java.util.function.Supplier;

public final class AuthBootstrap {
    private static AuthServices shared;
    private AuthBootstrap() {}

    public static synchronized AuthServices services() {
        if (shared == null) { shared = criar(System.getenv(), Clock.systemUTC()); }
        return shared;
    }

    public static AuthServices criar(Map<String, String> env, Clock clock) {
        SecretsManagerClient secrets = null;
        com.zaxxer.hikari.HikariDataSource datasource = null;
        try {
            Supplier<String> source;
            switch (env.getOrDefault("AUTH_KEY_PROVIDER", "")) {
                case "local-file" -> source = new LocalKeySource(env);
                case "secrets-manager" -> {
                    String secretId = env.get("AUTH_KEY_SECRET_ID");
                    String region = env.get("AWS_REGION");
                    if (secretId == null || secretId.isBlank() || region == null || region.isBlank()) {
                        throw new IllegalArgumentException("Secret ID e regiao obrigatorios");
                    }
                    secrets = SecretsManagerClient.builder().region(Region.of(region))
                            .httpClientBuilder(UrlConnectionHttpClient.builder()
                                    .connectionTimeout(Duration.ofSeconds(2)).socketTimeout(Duration.ofSeconds(2)))
                            .overrideConfiguration(config -> config.apiCallTimeout(Duration.ofSeconds(4))
                                    .apiCallAttemptTimeout(Duration.ofSeconds(2))).build();
                    source = new SecretsManagerKeySource(secrets, secretId);
                }
                default -> throw new IllegalArgumentException("AUTH_KEY_PROVIDER obrigatorio");
            }
            var keys = new RotatingKeyProvider(source, clock);
            var issuer = new Rs256TokenIssuer(keys, clock, env.get("AUTH_JWT_ISSUER"), env.get("AUTH_JWT_AUDIENCE"),
                    Integer.parseInt(env.getOrDefault("AUTH_JWT_TTL_SECONDS", "900")));
            datasource = AuthDatabase.criar(env);
            var ownedDatasource = datasource;
            var ownedSecrets = secrets;
            return new AuthServices(new AutenticarUsuarioUseCase(new JdbcIdentityTransaction(datasource),
                    new Argon2idPasswordHasher(), issuer, clock), new JwksService(keys), new JdbcLoginRateLimiter(datasource),
                    () -> {
                        ownedDatasource.close();
                        if (ownedSecrets != null) { ownedSecrets.close(); }
                    });
        } catch (RuntimeException exception) {
            if (datasource != null) { datasource.close(); }
            if (secrets != null) { secrets.close(); }
            throw exception;
        }
    }
}
