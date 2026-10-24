package br.com.fiap.oficina.auth.handler;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayV2HTTPEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayV2HTTPResponse;
import java.util.Map;

@Deprecated
public final class AuthHandler implements RequestHandler<APIGatewayV2HTTPEvent, APIGatewayV2HTTPResponse> {
    @Override
    public APIGatewayV2HTTPResponse handleRequest(APIGatewayV2HTTPEvent event, Context context) {
        return APIGatewayV2HTTPResponse.builder()
                .withStatusCode(503)
                .withHeaders(Map.of("Content-Type", "application/json", "Cache-Control", "no-store"))
                .withBody("{\"token\":null,\"message\":\"Autenticacao legada por CPF desativada.\"}")
                .build();
    }
}
