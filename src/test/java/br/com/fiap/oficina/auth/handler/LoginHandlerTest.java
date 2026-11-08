package br.com.fiap.oficina.auth.handler;

import br.com.fiap.oficina.auth.application.usecase.AutenticarUsuarioUseCase;
import br.com.fiap.oficina.auth.domain.exception.IdentityException;
import br.com.fiap.oficina.auth.domain.model.Usuario;
import br.com.fiap.oficina.auth.infrastructure.config.*;
import br.com.fiap.oficina.auth.infrastructure.security.*;
import com.amazonaws.services.lambda.runtime.events.APIGatewayV2HTTPEvent;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import java.time.*;
import java.util.*;
import static br.com.fiap.oficina.auth.support.AuthFixtures.*;
import static br.com.fiap.oficina.auth.domain.exception.IdentityException.Motivo.*;
import static org.junit.jupiter.api.Assertions.*;

class LoginHandlerTest {
    private static final String PATH = "/api/v1/auth/login";
    private static final String BODY = "{\"email\":\"pessoa@example.test\",\"senha\":\"" + SENHA + "\"}";
    private final Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);

    private AuthServices services() {
        var hasher = new Argon2idPasswordHasher();
        var usuario = Usuario.criar("pessoa@example.test", "Ficticio", null, hasher.hash(SENHA.toCharArray()), NOW);
        var provider = provider(clock);
        return new AuthServices(new AutenticarUsuarioUseCase(new Store(usuario), hasher,
                new Rs256TokenIssuer(provider, clock, ISSUER, AUDIENCE, 900), clock), new JwksService(provider), (ip, email) -> {});
    }

    @Test
    void loginEJwksUsamFormatoHttpV2ComHeadersCorretosEBase64() throws Exception {
        var services = services();
        var handler = new AuthHandler(() -> services);
        var event = event("POST", PATH, BODY);
        event.setIsBase64Encoded(true);
        event.setBody(Base64.getEncoder().encodeToString(BODY.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        var response = handler.handleRequest(event, null);
        assertEquals(200, response.getStatusCode());
        assertEquals("no-store", response.getHeaders().get("Cache-Control"));
        var json = new ObjectMapper().readTree(response.getBody());
        assertEquals(Set.of("accessToken", "tokenType", "expiresIn"), fieldNames(json));
        assertEquals(900, json.get("expiresIn").asInt());
        assertEquals("Bearer", json.get("tokenType").asText());
        var jwks = handler.handleRequest(event("GET", "/.well-known/jwks.json", null), null);
        assertEquals(200, jwks.getStatusCode());
        assertEquals("public, max-age=60, must-revalidate", jwks.getHeaders().get("Cache-Control"));
        assertFalse(jwks.getBody().contains("private"));
        assertFalse(jwks.getBody().contains("password"));
    }

    private Set<String> fieldNames(com.fasterxml.jackson.databind.JsonNode json) {
        Set<String> names = new HashSet<>();
        json.fieldNames().forEachRemaining(names::add);
        return names;
    }

    @Test
    void validaJsonPayloadMetodoERotaAntesDeInicializarDependencias() {
        var handler = new AuthHandler(() -> { fail("Nao inicializar dependencias"); return null; });
        assertEquals(400, handler.handleRequest(null, null).getStatusCode());
        assertEquals(400, handler.handleRequest(new APIGatewayV2HTTPEvent(), null).getStatusCode());
        assertEquals(404, handler.handleRequest(event("POST", "/auth/cpf", BODY), null).getStatusCode());
        var wrongMethod = handler.handleRequest(event("GET", PATH, null), null);
        assertEquals(405, wrongMethod.getStatusCode());
        assertEquals("POST", wrongMethod.getHeaders().get("Allow"));
        for (String body : new String[]{"", "null", "[]", "{}", "{", BODY + "{}", "x".repeat(8193),
                "{\"email\":\"a@example.test\",\"senha\":\"short\"}",
                BODY.replace("\"email\":", "\"email\":\"x\",\"email\":"),
                BODY.replace("}", ",\"roles\":[\"GERENTE\"]}"),
                BODY.replace("}", ",\"cpf\":\"12345678909\"}"),
                BODY.replace("\"pessoa@example.test\"", "42")}) {
            assertEquals(400, handler.handleRequest(event("POST", PATH, body), null).getStatusCode(), body);
        }
        var missing = event("POST", PATH, null);
        assertEquals(400, handler.handleRequest(missing, null).getStatusCode());
        missing.setBody(BODY);
        missing.setHeaders(Map.of("Content-Type", "text/plain"));
        assertEquals(400, handler.handleRequest(missing, null).getStatusCode());
        missing.setHeaders(null);
        assertEquals(400, handler.handleRequest(missing, null).getStatusCode());
        for (String invalid : List.of("!bad", "/w==")) {
            var base64 = event("POST", PATH, invalid);
            base64.setIsBase64Encoded(true);
            assertEquals(400, handler.handleRequest(base64, null).getStatusCode());
        }
    }

    @Test
    void mensagensGenericasEStatusSegurosParaCadaFalha() {
        var services = services();
        var good = new AuthHandler(() -> services);
        var incorrect = good.handleRequest(event("POST", PATH, BODY.replace(SENHA, "outra-senha-incorreta")), null);
        var absent = good.handleRequest(event("POST", PATH, BODY.replace("pessoa@", "ausente@")), null);
        assertEquals(401, incorrect.getStatusCode());
        assertEquals(incorrect.getBody(), absent.getBody());
        for (var reason : List.of(LIMITE_EXCEDIDO, PERSISTENCIA, CONCORRENCIA, INVALIDO, DUPLICADO)) {
            var handler = new AuthHandler(() -> new AuthServices(services.login(), services.jwks(), (ip, email) -> {
                throw new IdentityException(reason);
            }));
            int expected = switch (reason) {
                case LIMITE_EXCEDIDO -> 429;
                case PERSISTENCIA, CONCORRENCIA -> 503;
                case INVALIDO -> 400;
                default -> 500;
            };
            var response = handler.handleRequest(event("POST", PATH, BODY), null);
            assertEquals(expected, response.getStatusCode());
            assertFalse(response.getBody().contains(SENHA));
            if (expected == 429) { assertEquals("60", response.getHeaders().get("Retry-After")); }
        }
        var config = new AuthHandler(() -> { throw new IllegalArgumentException("sensitive"); });
        assertEquals(503, config.handleRequest(event("POST", PATH, BODY), null).getStatusCode());
        var broken = new AuthHandler(() -> { throw new IllegalStateException("sensitive"); });
        var response = broken.handleRequest(event("GET", "/.well-known/jwks.json", null), null);
        assertEquals(500, response.getStatusCode());
        assertFalse(response.getBody().contains("sensitive"));
    }
}
