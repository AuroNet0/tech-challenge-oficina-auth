package br.com.fiap.oficina.auth.handler;

import com.amazonaws.services.lambda.runtime.events.APIGatewayV2HTTPEvent;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class AuthHandlerTest {
    @Test
    void recusaTodosOsEventosSemConfigurarBancoOuJwt() {
        var handler = new AuthHandler();
        for (var event : new APIGatewayV2HTTPEvent[]{null, APIGatewayV2HTTPEvent.builder()
                .withBody("{\"cpf\":\"12345678909\",\"papel\":\"GERENTE\"}").build()}) {
            var response = handler.handleRequest(event, null);
            assertEquals(503, response.getStatusCode());
            assertEquals("no-store", response.getHeaders().get("Cache-Control"));
            assertTrue(response.getBody().contains("\"token\":null"));
        }
    }
}
