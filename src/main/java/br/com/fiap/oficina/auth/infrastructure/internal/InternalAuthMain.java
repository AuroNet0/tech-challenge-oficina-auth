package br.com.fiap.oficina.auth.infrastructure.internal;

import br.com.fiap.oficina.auth.infrastructure.config.AuthDatabase;
import br.com.fiap.oficina.auth.infrastructure.persistence.jdbc.JdbcIdentityTransaction;
import br.com.fiap.oficina.auth.infrastructure.security.*;
import java.net.*;
import java.time.Clock;

public final class InternalAuthMain {
    private InternalAuthMain() {}

    public static void main(String[] args) throws Exception {
        var env = System.getenv();
        var clock = Clock.systemUTC();
        System.setProperty("sun.net.httpserver.maxReqTime", "3");
        System.setProperty("sun.net.httpserver.maxRspTime", "3");
        System.setProperty("sun.net.httpserver.timerMillis", "1000");
        System.setProperty("sun.net.httpserver.maxConnections", "64");
        System.setProperty("sun.net.httpserver.maxIdleConnections", "16");
        System.setProperty("sun.net.httpserver.idleInterval", "10");
        var tls = new InternalTls(env);
        var keys = new TrustedJwksProvider(URI.create(InternalTls.required(env, "AUTH_JWKS_URI")), clock);
        var verifier = new InternalUserTokenVerifier(keys, env.get("AUTH_JWT_ISSUER"), env.get("AUTH_JWT_AUDIENCE"), clock);
        var database = AuthDatabase.criar(env, true);
        try {
            var server = new InternalAuthServer(new InetSocketAddress("0.0.0.0",
                    Integer.parseInt(env.getOrDefault("AUTH_INTERNAL_PORT", "8443"))), tls,
                    new JdbcIdentityTransaction(database), verifier, clock, () -> {
                        if (keys.publicas().isEmpty()) { throw KeyDocuments.indisponivel(); }
                        try (var connection = database.getConnection(); var statement = connection.createStatement()) {
                            statement.setQueryTimeout(1);
                            statement.execute("SELECT id FROM usuarios LIMIT 0");
                            statement.execute("SELECT usuario_id, papel FROM usuario_papeis LIMIT 0");
                            statement.execute("SELECT usuario_id, cliente_id FROM usuario_clientes LIMIT 0");
                        }
                    });
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                server.close();
                database.close();
                keys.close();
                System.out.println("AUTH_INTERNAL_STOPPED");
            }, "auth-internal-shutdown"));
            server.start();
            System.out.println("AUTH_INTERNAL_STARTED");
        } catch (Exception exception) {
            database.close();
            keys.close();
            throw exception;
        }
    }
}
