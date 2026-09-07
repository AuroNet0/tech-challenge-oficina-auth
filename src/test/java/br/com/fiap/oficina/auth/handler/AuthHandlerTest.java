package br.com.fiap.oficina.auth.handler;

import br.com.fiap.oficina.auth.model.AuthRequest;
import br.com.fiap.oficina.auth.model.AuthResponse;
import br.com.fiap.oficina.auth.model.ClienteAuth;
import br.com.fiap.oficina.auth.repository.ClienteRepository;
import br.com.fiap.oficina.auth.service.CpfValidator;
import br.com.fiap.oficina.auth.service.JwtService;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertFalse;

class AuthHandlerTest {

    private static final String JWT_SECRET = "12345678901234567890123456789012";
    private static final Clock FIXED_CLOCK = Clock.fixed(Instant.parse("2026-09-07T12:00:00Z"), ZoneOffset.UTC);

    @Test
    void shouldReturnInvalidRequestWhenRequestIsNull() {
        AuthHandler handler = createHandler(Optional.empty());

        AuthResponse response = handler.handleRequest(null, null);

        assertNotNull(response);
        assertNull(response.getToken());
        assertEquals("Requisi\u00e7\u00e3o inv\u00e1lida.", response.getMessage());
    }

    @Test
    void shouldReturnInvalidCpfMessageWhenCpfIsInvalid() {
        AuthHandler handler = createHandler(Optional.empty());
        AuthRequest request = new AuthRequest("12345678900");

        AuthResponse response = handler.handleRequest(request, null);

        assertNotNull(response);
        assertNull(response.getToken());
        assertEquals("CPF inv\u00e1lido.", response.getMessage());
    }

    @Test
    void shouldReturnNotFoundMessageWhenValidCpfDoesNotMatchCliente() {
        AuthHandler handler = createHandler(Optional.empty());
        AuthRequest request = new AuthRequest("12345678909");

        AuthResponse response = handler.handleRequest(request, null);

        assertNotNull(response);
        assertNull(response.getToken());
        assertEquals("Cliente n\u00e3o encontrado.", response.getMessage());
    }

    @Test
    void shouldReturnInactiveMessageWhenClienteIsInactive() {
        ClienteAuth cliente = new ClienteAuth(1L, "Cliente Teste", "12345678909", false);
        AuthHandler handler = createHandler(Optional.of(cliente));
        AuthRequest request = new AuthRequest("12345678909");

        AuthResponse response = handler.handleRequest(request, null);

        assertNotNull(response);
        assertNull(response.getToken());
        assertEquals("Cliente inativo.", response.getMessage());
    }

    @Test
    void shouldReturnTemporaryTokenMessageWhenClienteIsActive() {
        ClienteAuth cliente = new ClienteAuth(1L, "Cliente Teste", "12345678909", true);
        AuthHandler handler = createHandler(Optional.of(cliente));
        AuthRequest request = new AuthRequest("12345678909");

        AuthResponse response = handler.handleRequest(request, null);

        assertNotNull(response);
        assertNotNull(response.getToken());
        assertFalse(response.getToken().isBlank());
        assertEquals("Autentica\u00e7\u00e3o realizada com sucesso.", response.getMessage());
    }

    private AuthHandler createHandler(Optional<ClienteAuth> cliente) {
        return new AuthHandler(new CpfValidator(), new FakeClienteRepository(cliente), new JwtService(JWT_SECRET, FIXED_CLOCK));
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
