package integration;

import br.com.fiap.oficina.auth.handler.AuthHandler;
import br.com.fiap.oficina.auth.infrastructure.config.*;
import br.com.fiap.oficina.auth.infrastructure.persistence.jdbc.JdbcIdentityTransaction;
import br.com.fiap.oficina.auth.infrastructure.security.*;
import br.com.fiap.oficina.auth.application.port.out.IdentidadeAcessoCliente;
import br.com.fiap.oficina.auth.application.usecase.VerificarAcessoClienteUseCase;
import br.com.fiap.oficina.auth.domain.exception.IdentityException;
import com.amazonaws.services.lambda.runtime.events.APIGatewayV2HTTPEvent;
import com.sun.net.httpserver.*;
import com.fasterxml.jackson.databind.json.JsonMapper;
import javax.net.ssl.SSLContext;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.*;
import java.util.concurrent.Executors;

public final class AuthLocalRuntime {
    public static void main(String[] args) throws Exception {
        var env = System.getenv();
        if (!"local".equals(env.get("AUTH_ENVIRONMENT")) || env.containsKey("AWS_LAMBDA_FUNCTION_NAME")) {
            throw new IllegalStateException("Local E2E runtime only");
        }
        var clock = Clock.systemUTC();
        var handler = new AuthHandler();
        var keys = new RotatingKeyProvider(new LocalKeySource(env), clock);
        var verifier = new InternalUserTokenVerifier(keys, env.get("AUTH_JWT_ISSUER"), env.get("AUTH_JWT_AUDIENCE"), clock);
        var database = AuthDatabase.criar(env);
        var json = JsonMapper.builder().build();
        var server = HttpsServer.create(new InetSocketAddress("0.0.0.0", 8443), 32);
        server.setHttpsConfigurator(new HttpsConfigurator(SSLContext.getDefault()) {
            @Override
            public void configure(HttpsParameters parameters) {
                var ssl = getSSLContext().getDefaultSSLParameters();
                ssl.setWantClientAuth(true);
                parameters.setSSLParameters(ssl);
            }
        });
        server.setExecutor(Executors.newFixedThreadPool(8));
        server.createContext("/", exchange -> {
            int status;
            String body;
            Map<String, String> headers = Map.of("Content-Type", "application/json", "Cache-Control", "no-store");
            try {
                byte[] bytes = exchange.getRequestBody().readNBytes(16385);
                if (bytes.length > 16384) { throw new IllegalArgumentException(); }
                String path = exchange.getRequestURI().getPath();
                if ("/health".equals(path) && "GET".equals(exchange.getRequestMethod())) {
                    keys.ativa();
                    status = 200;
                    body = "{\"status\":\"UP\"}";
                } else if ("/internal/v1/identity/client-access/check".equals(path)) {
                    var certificates = ((HttpsExchange) exchange).getSSLSession().getPeerCertificates();
                    if (!"CN=os-service".equals(((java.security.cert.X509Certificate) certificates[0])
                            .getSubjectX500Principal().getName())) {
                        status = 403;
                        body = "{}";
                    } else if (!"POST".equals(exchange.getRequestMethod())
                            || !"application/json".equals(exchange.getRequestHeaders().getFirst("Content-Type"))) {
                        status = 400;
                        body = "{}";
                    } else {
                        var request = InternalClientAccessRequest.parse(bytes);
                        request.exigirAtual(clock);
                        var user = verifier.verificar(request.userAccessToken());
                        var check = new VerificarAcessoClienteUseCase(new JdbcIdentityTransaction(database), target -> {
                            if (!target.equals(request.clienteId())) { throw new IllegalArgumentException(); }
                            return new IdentidadeAcessoCliente(user.usuarioId(), "os-service", target, user.expiraEm());
                        }, Set.of("os-service"), clock);
                        body = json.writeValueAsString(check.executar(request.clienteId().toString()));
                        status = 200;
                    }
                } else {
                    var http = APIGatewayV2HTTPEvent.RequestContext.Http.builder().withMethod(exchange.getRequestMethod())
                            .withPath(path).withSourceIp(exchange.getRemoteAddress().getAddress().getHostAddress()).build();
                    Map<String, String> eventHeaders = new HashMap<>();
                    exchange.getRequestHeaders().forEach((name, values) -> eventHeaders.put(name, values.getFirst()));
                    var event = APIGatewayV2HTTPEvent.builder().withVersion("2.0").withRawPath(path)
                            .withRouteKey(exchange.getRequestMethod() + " " + path).withHeaders(eventHeaders)
                            .withBody(new String(bytes, StandardCharsets.UTF_8)).withIsBase64Encoded(false)
                            .withRequestContext(APIGatewayV2HTTPEvent.RequestContext.builder().withHttp(http).build()).build();
                    var response = handler.handleRequest(event, null);
                    status = response.getStatusCode();
                    body = response.getBody();
                    headers = response.getHeaders();
                }
            } catch (javax.net.ssl.SSLPeerUnverifiedException exception) {
                status = 401;
                body = "{}";
            } catch (IdentityException exception) {
                status = switch (exception.motivo()) {
                    case CREDENCIAIS_INVALIDAS -> 401;
                    case NAO_AUTORIZADO -> 403;
                    case INVALIDO -> 400;
                    default -> 503;
                };
                body = "{}";
            } catch (Exception exception) {
                status = 503;
                body = "{}";
            }
            headers.forEach((name, value) -> exchange.getResponseHeaders().set(name, value));
            byte[] response = body.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(status, response.length);
            try (var output = exchange.getResponseBody()) { output.write(response); }
            exchange.close();
        });
        server.start();
        System.out.println("AUTH_LOCAL_API_GATEWAY_V2_READY");
    }
}
