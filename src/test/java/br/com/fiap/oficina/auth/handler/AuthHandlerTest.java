package br.com.fiap.oficina.auth.handler;

import com.amazonaws.services.lambda.runtime.events.APIGatewayV2HTTPEvent;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class AuthHandlerTest {
    @Test
    void rotaInternaPermaneceInacessivelMesmoComHeadersDeIdentidadeForjados() {
        var handler = new AuthHandler(() -> {
            fail("Rota interna nao pode inicializar servicos");
            return null;
        });
        for (String method : new String[]{"POST", "GET", "OPTIONS"}) {
            var event = br.com.fiap.oficina.auth.support.AuthFixtures.event(method,
                    "/internal/v1/identity/client-access/check", "{\"clienteId\":\"00000000-0000-0000-0000-000000000001\"}");
            event.setHeaders(java.util.Map.of("Authorization", "Bearer token-forjado", "X-User-Id", "outro-usuario",
                    "X-Roles", "CLIENTE", "X-Service-Id", "os-service"));
            var response = handler.handleRequest(event, null);
            assertEquals(404, response.getStatusCode());
            assertEquals("no-store", response.getHeaders().get("Cache-Control"));
            assertFalse(response.getBody().contains("autorizado"));
        }
    }

    @Test
    void recusaTodosOsEventosSemConfigurarBancoOuJwt() {
        var handler = new AuthHandler();
        for (var event : new APIGatewayV2HTTPEvent[]{null, APIGatewayV2HTTPEvent.builder()
                .withBody("{\"cpf\":\"12345678909\",\"papel\":\"GERENTE\"}").build()}) {
            var response = handler.handleRequest(event, null);
            assertEquals(400, response.getStatusCode());
            assertEquals("no-store", response.getHeaders().get("Cache-Control"));
            assertFalse(response.getBody().contains("accessToken"));
        }
    }
}
