package br.com.fiap.oficina.auth.handler;

import br.com.fiap.oficina.auth.application.usecase.AutenticarUsuarioUseCase;
import br.com.fiap.oficina.auth.domain.exception.IdentityException;
import br.com.fiap.oficina.auth.infrastructure.config.*;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayV2HTTPEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayV2HTTPResponse;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import java.nio.ByteBuffer;
import java.nio.charset.*;
import java.util.*;
import java.util.function.Supplier;

public final class AuthHandler implements RequestHandler<APIGatewayV2HTTPEvent, APIGatewayV2HTTPResponse> {
    private static final int MAX_BODY = 8192;
    private static final JsonMapper JSON = JsonMapper.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS).build();
    private final Supplier<AuthServices> services;

    public AuthHandler() { this(AuthBootstrap::services); }
    public AuthHandler(Supplier<AuthServices> services) { this.services = services; }

    @Override
    public APIGatewayV2HTTPResponse handleRequest(APIGatewayV2HTTPEvent event, Context context) {
        if (event == null || event.getRequestContext() == null || event.getRequestContext().getHttp() == null
                || !"2.0".equals(event.getVersion())) { return erro(400, "Entrada invalida."); }
        String method = event.getRequestContext().getHttp().getMethod();
        String path = event.getRawPath();
        String expected;
        if ("/api/v1/auth/login".equals(path)) { expected = "POST"; }
        else if ("/.well-known/jwks.json".equals(path)) { expected = "GET"; }
        else { return erro(404, "Rota nao encontrada."); }
        if (!expected.equals(method)) {
            return resposta(405, Map.of("message", "Metodo nao permitido."), Map.of("Allow", expected));
        }
        try {
            if ("GET".equals(method)) {
                return resposta(200, services.get().jwks().documento(),
                        Map.of("Cache-Control", "public, max-age=60, must-revalidate"));
            }
            return login(event);
        } catch (IdentityException exception) {
            return switch (exception.motivo()) {
                case CREDENCIAIS_INVALIDAS, INATIVO, NAO_ENCONTRADO -> erro(401, "Credenciais invalidas.");
                case INVALIDO -> erro(400, "Entrada invalida.");
                case LIMITE_EXCEDIDO -> resposta(429, Map.of("message", "Limite de tentativas excedido."), Map.of("Retry-After", "60"));
                case PERSISTENCIA, CONCORRENCIA -> erro(503, "Servico temporariamente indisponivel.");
                default -> erro(500, "Erro interno.");
            };
        } catch (IllegalArgumentException exception) {
            return erro(503, "Servico temporariamente indisponivel.");
        } catch (Exception exception) {
            return erro(500, "Erro interno.");
        }
    }

    private APIGatewayV2HTTPResponse login(APIGatewayV2HTTPEvent event) {
        char[] senha = null;
        try {
            String contentType = event.getHeaders() == null ? "" : event.getHeaders().entrySet().stream()
                    .filter(entry -> entry.getKey().equalsIgnoreCase("Content-Type"))
                    .map(Map.Entry::getValue).findFirst().orElse("");
            if (contentType == null || !contentType.toLowerCase(Locale.ROOT).matches("application/json(?:;.*)?")
                    || event.getBody() == null || event.getBody().length() > MAX_BODY) {
                return erro(400, "Entrada invalida.");
            }
            byte[] body;
            try {
                body = Boolean.TRUE.equals(event.getIsBase64Encoded())
                        ? Base64.getDecoder().decode(event.getBody()) : event.getBody().getBytes(StandardCharsets.UTF_8);
            } catch (IllegalArgumentException exception) {
                return erro(400, "Entrada invalida.");
            }
            if (body.length > MAX_BODY) { return erro(400, "Entrada invalida."); }
            String decoded = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(body)).toString();
            var request = JSON.readTree(decoded);
            if (request == null || !request.isObject() || request.size() != 2
                    || !request.path("email").isTextual() || !request.path("senha").isTextual()) {
                return erro(400, "Entrada invalida.");
            }
            senha = request.get("senha").textValue().toCharArray();
            String email = AutenticarUsuarioUseCase.validar(request.get("email").textValue(), senha);
            var dependencies = services.get();
            dependencies.limiter().exigir(event.getRequestContext().getHttp().getSourceIp(), email);
            return resposta(200, dependencies.login().executar(email, senha), Map.of());
        } catch (com.fasterxml.jackson.core.JsonProcessingException | CharacterCodingException exception) {
            return erro(400, "Entrada invalida.");
        } finally {
            if (senha != null) { Arrays.fill(senha, '\u0000'); }
        }
    }

    private APIGatewayV2HTTPResponse erro(int status, String message) {
        return resposta(status, Map.of("message", message), Map.of());
    }

    private APIGatewayV2HTTPResponse resposta(int status, Object body, Map<String, String> extra) {
        var headers = new HashMap<>(Map.of("Content-Type", "application/json", "Cache-Control", "no-store",
                "Pragma", "no-cache", "X-Content-Type-Options", "nosniff"));
        headers.putAll(extra);
        try {
            return APIGatewayV2HTTPResponse.builder().withStatusCode(status).withHeaders(headers)
                    .withBody(JSON.writeValueAsString(body)).build();
        } catch (Exception exception) {
            return APIGatewayV2HTTPResponse.builder().withStatusCode(500).withHeaders(headers)
                    .withBody("{\"message\":\"Erro interno.\"}").build();
        }
    }
}
