package br.com.fiap.oficina.auth.infrastructure.internal;

import br.com.fiap.oficina.auth.application.port.out.*;
import br.com.fiap.oficina.auth.application.usecase.VerificarAcessoClienteUseCase;
import br.com.fiap.oficina.auth.domain.exception.IdentityException;
import br.com.fiap.oficina.auth.infrastructure.security.InternalClientAccessRequest;
import br.com.fiap.oficina.auth.infrastructure.security.InternalUserTokenVerifier;
import com.sun.net.httpserver.*;
import javax.net.ssl.SSLPeerUnverifiedException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.Set;
import java.util.concurrent.*;

public final class InternalAuthServer implements AutoCloseable {
    public static final String ACCESS_PATH = "/internal/v1/identity/client-access/check";
    private final HttpsServer server;
    private final ExecutorService executor;
    private final InternalTls tls;
    private final IdentityTransaction transaction;
    private final InternalUserTokenVerifier verifier;
    private final Clock clock;
    private final Readiness readiness;
    private volatile boolean closing;

    @FunctionalInterface
    public interface Readiness { void check() throws Exception; }

    public InternalAuthServer(InetSocketAddress address, InternalTls tls, IdentityTransaction transaction,
                              InternalUserTokenVerifier verifier, Clock clock, Readiness readiness) throws IOException {
        this.tls = tls;
        this.transaction = transaction;
        this.verifier = verifier;
        this.clock = clock;
        this.readiness = readiness;
        server = HttpsServer.create(address, 32);
        server.setHttpsConfigurator(new HttpsConfigurator(tls.context()) {
            @Override
            public void configure(HttpsParameters parameters) {
                var ssl = getSSLContext().getDefaultSSLParameters();
                ssl.setProtocols(new String[]{"TLSv1.3", "TLSv1.2"});
                ssl.setWantClientAuth(true);
                parameters.setSSLParameters(ssl);
            }
        });
        executor = new ThreadPoolExecutor(8, 8, 0, TimeUnit.SECONDS, new ArrayBlockingQueue<>(32),
                new ThreadPoolExecutor.AbortPolicy());
        server.setExecutor(executor);
        server.createContext("/", this::handle);
    }

    public void start() { server.start(); }
    public int port() { return server.getAddress().getPort(); }

    private void handle(HttpExchange raw) throws IOException {
        try (var exchange = (HttpsExchange) raw) {
            int status = 503;
            String body = "{}";
            try {
                String path = exchange.getRequestURI().getRawPath();
                if (closing) { status = 503; }
                else if ("GET".equals(exchange.getRequestMethod()) && "/health/live".equals(path)) {
                    status = 200;
                    body = "{\"status\":\"UP\"}";
                } else if ("GET".equals(exchange.getRequestMethod()) && "/health/ready".equals(path)) {
                    tls.checkValidity();
                    readiness.check();
                    status = 200;
                    body = "{\"status\":\"UP\"}";
                } else if (!ACCESS_PATH.equals(path)) { status = 404; }
                else if (!tls.isOs(exchange.getSSLSession())) { status = 403; }
                else if (!"POST".equals(exchange.getRequestMethod()) || exchange.getRequestURI().getRawQuery() != null
                        || exchange.getRequestHeaders().getOrDefault("Content-Type", java.util.List.of()).size() != 1
                        || !"application/json".equals(exchange.getRequestHeaders().getFirst("Content-Type"))) { status = 400; }
                else {
                    tls.checkValidity();
                    var request = InternalClientAccessRequest.parse(exchange.getRequestBody().readNBytes(12289));
                    request.exigirAtual(clock);
                    exchange.getResponseHeaders().set("X-Correlation-ID", request.requestId().toString());
                    var user = verifier.verificar(request.userAccessToken());
                    var check = new VerificarAcessoClienteUseCase(transaction, target ->
                            new IdentidadeAcessoCliente(user.usuarioId(), "os-service", target, user.expiraEm()),
                            Set.of("os-service"), clock);
                    body = check.executar(request.clienteId().toString()).autorizado()
                            ? "{\"autorizado\":true}" : "{\"autorizado\":false}";
                    status = 200;
                }
            } catch (SSLPeerUnverifiedException exception) { status = 401; }
            catch (java.security.cert.CertificateException exception) { status = 401; }
            catch (IdentityException exception) {
                status = switch (exception.motivo()) {
                    case CREDENCIAIS_INVALIDAS -> 401;
                    case NAO_AUTORIZADO -> 403;
                    case INVALIDO -> 400;
                    default -> 503;
                };
            } catch (Exception exception) { status = 503; }
            var headers = exchange.getResponseHeaders();
            headers.set("Content-Type", "application/json");
            headers.set("Cache-Control", "no-store");
            headers.set("X-Content-Type-Options", "nosniff");
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(status, bytes.length);
            exchange.getResponseBody().write(bytes);
        }
    }

    @Override
    public void close() {
        closing = true;
        server.stop(5);
        executor.shutdownNow();
    }
}
