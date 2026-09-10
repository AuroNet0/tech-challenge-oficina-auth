package br.com.fiap.oficina.auth.handler;

import br.com.fiap.oficina.auth.model.AuthResponse;
import br.com.fiap.oficina.auth.model.ClienteAuth;
import br.com.fiap.oficina.auth.repository.ClienteRepository;
import br.com.fiap.oficina.auth.service.CpfValidator;
import br.com.fiap.oficina.auth.service.JwtService;
import com.amazonaws.services.lambda.runtime.events.APIGatewayV2HTTPEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayV2HTTPResponse;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

class AuthHandlerTest {

    private static final String JWT_SECRET = "12345678901234567890123456789012";
    private static final Clock FIXED_CLOCK = Clock.fixed(Instant.parse("2026-09-07T12:00:00Z"), ZoneOffset.UTC);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @Test
    void shouldReturnInvalidRequestWhenRequestIsNull() throws JsonProcessingException {
        AuthHandler handler = createHandler(Optional.empty());

        APIGatewayV2HTTPResponse response = handler.handleRequest(null, null);

        assertResponse(response, 400, null, "Requisi\u00e7\u00e3o inv\u00e1lida.");
    }

    @Test
    void shouldReturnInvalidCpfMessageWhenCpfIsInvalid() throws JsonProcessingException {
        AuthHandler handler = createHandler(Optional.empty());
        APIGatewayV2HTTPEvent event = createEvent("{\"cpf\":\"12345678900\"}");

        APIGatewayV2HTTPResponse response = handler.handleRequest(event, null);

        assertResponse(response, 400, null, "CPF inv\u00e1lido.");
    }

    @Test
    void shouldReturnNotFoundMessageWhenValidCpfDoesNotMatchCliente() throws JsonProcessingException {
        AuthHandler handler = createHandler(Optional.empty());
        APIGatewayV2HTTPEvent event = createEvent("{\"cpf\":\"12345678909\"}");

        APIGatewayV2HTTPResponse response = handler.handleRequest(event, null);

        assertResponse(response, 404, null, "Cliente n\u00e3o encontrado.");
    }

    @Test
    void shouldReturnInactiveMessageWhenClienteIsInactive() throws JsonProcessingException {
        ClienteAuth cliente = new ClienteAuth(1L, "Cliente Teste", "12345678909", false);
        AuthHandler handler = createHandler(Optional.of(cliente));
        APIGatewayV2HTTPEvent event = createEvent("{\"cpf\":\"12345678909\"}");

        APIGatewayV2HTTPResponse response = handler.handleRequest(event, null);

        assertResponse(response, 403, null, "Cliente inativo.");
    }

    @Test
    void shouldReturnTokenWhenClienteIsActive() throws JsonProcessingException {
        ClienteAuth cliente = new ClienteAuth(1L, "Cliente Teste", "12345678909", true);
        AuthHandler handler = createHandler(Optional.of(cliente));
        APIGatewayV2HTTPEvent event = createEvent("{\"cpf\":\"12345678909\"}");

        APIGatewayV2HTTPResponse response = handler.handleRequest(event, null);

        assertEquals(200, response.getStatusCode());
        assertEquals("application/json", response.getHeaders().get("Content-Type"));

        AuthResponse authResponse = OBJECT_MAPPER.readValue(response.getBody(), AuthResponse.class);
        assertNotNull(authResponse.getToken());
        assertFalse(authResponse.getToken().isBlank());
        assertEquals("Autentica\u00e7\u00e3o realizada com sucesso.", authResponse.getMessage());
    }

    private AuthHandler createHandler(Optional<ClienteAuth> cliente) {
        return new AuthHandler(new CpfValidator(), new FakeClienteRepository(cliente), new JwtService(JWT_SECRET, FIXED_CLOCK));
    }

    private APIGatewayV2HTTPEvent createEvent(String body) {
        APIGatewayV2HTTPEvent event = new APIGatewayV2HTTPEvent();
        event.setBody(body);
        return event;
    }

    private void assertResponse(
            APIGatewayV2HTTPResponse response,
            int statusCode,
            String expectedToken,
            String expectedMessage
    ) throws JsonProcessingException {
        assertEquals(statusCode, response.getStatusCode());
        assertEquals("application/json", response.getHeaders().get("Content-Type"));

        AuthResponse authResponse = OBJECT_MAPPER.readValue(response.getBody(), AuthResponse.class);
        assertEquals(expectedToken, authResponse.getToken());
        assertEquals(expectedMessage, authResponse.getMessage());
    }

    private static class FakeClienteRepository implements ClienteRepository {

        private final Optional<ClienteAuth> cliente;

        private FakeClienteRepository(Optional<ClienteAuth> cliente) {
            this.cliente = cliente;
        }

        @Override
        public Optional<ClienteAuth> findByCpf(String cpf) {
            return cliente;
        }
    }
}
