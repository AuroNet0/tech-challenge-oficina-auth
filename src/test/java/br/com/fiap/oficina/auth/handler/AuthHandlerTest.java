package br.com.fiap.oficina.auth.handler;

import br.com.fiap.oficina.auth.model.AuthRequest;
import br.com.fiap.oficina.auth.model.AuthResponse;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

class AuthHandlerTest {

    @Test
    void shouldProcessBasicRequestWithoutError() {
        AuthHandler handler = new AuthHandler();
        AuthRequest request = new AuthRequest("12345678909");

        AuthResponse response = assertDoesNotThrow(() -> handler.handleRequest(request, null));

        assertNotNull(response);
        assertNull(response.getToken());
        assertNotNull(response.getMessage());
    }
}
