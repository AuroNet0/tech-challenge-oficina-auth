package br.com.fiap.oficina.auth.handler;

import br.com.fiap.oficina.auth.model.AuthRequest;
import br.com.fiap.oficina.auth.model.AuthResponse;
import br.com.fiap.oficina.auth.model.ClienteAuth;
import br.com.fiap.oficina.auth.repository.ClienteRepository;
import br.com.fiap.oficina.auth.repository.JdbcClienteRepository;
import br.com.fiap.oficina.auth.service.CpfValidator;
import br.com.fiap.oficina.auth.service.JwtService;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayV2HTTPEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayV2HTTPResponse;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Map;
import java.util.Optional;

public class AuthHandler implements RequestHandler<APIGatewayV2HTTPEvent, APIGatewayV2HTTPResponse> {

    private static final String CONTENT_TYPE = "Content-Type";
    private static final String APPLICATION_JSON = "application/json";

    private final CpfValidator cpfValidator;
    private final ClienteRepository clienteRepository;
    private final JwtService jwtService;
    private final ObjectMapper objectMapper;

    public AuthHandler() {
        this(new CpfValidator(), new JdbcClienteRepository(), new JwtService(), new ObjectMapper());
    }

    AuthHandler(CpfValidator cpfValidator, ClienteRepository clienteRepository, JwtService jwtService) {
        this(cpfValidator, clienteRepository, jwtService, new ObjectMapper());
    }

    AuthHandler(
            CpfValidator cpfValidator,
            ClienteRepository clienteRepository,
            JwtService jwtService,
            ObjectMapper objectMapper
    ) {
        this.cpfValidator = cpfValidator;
        this.clienteRepository = clienteRepository;
        this.jwtService = jwtService;
        this.objectMapper = objectMapper;
    }

    @Override
    public APIGatewayV2HTTPResponse handleRequest(APIGatewayV2HTTPEvent event, Context context) {
        AuthRequest request = readRequest(event);

        if (request == null) {
            return httpResponse(400, new AuthResponse(null, "Requisi\u00e7\u00e3o inv\u00e1lida."));
        }

        try {
            return authenticate(request);
        } catch (Exception exception) {
            return httpResponse(500, new AuthResponse(null, "Erro interno."));
        }
    }

    private APIGatewayV2HTTPResponse authenticate(AuthRequest request) {
        if (!cpfValidator.isValid(request.getCpf())) {
            return httpResponse(400, new AuthResponse(null, "CPF inv\u00e1lido."));
        }

        Optional<ClienteAuth> cliente = clienteRepository.findByCpf(request.getCpf());

        if (cliente.isEmpty()) {
            return httpResponse(404, new AuthResponse(null, "Cliente n\u00e3o encontrado."));
        }

        if (!cliente.get().isAtivo()) {
            return httpResponse(403, new AuthResponse(null, "Cliente inativo."));
        }

        String token = jwtService.generateToken(cliente.get());
        return httpResponse(200, new AuthResponse(token, "Autentica\u00e7\u00e3o realizada com sucesso."));
    }

    private AuthRequest readRequest(APIGatewayV2HTTPEvent event) {
        if (event == null || event.getBody() == null || event.getBody().isBlank()) {
            return null;
        }

        try {
            return objectMapper.readValue(event.getBody(), AuthRequest.class);
        } catch (JsonProcessingException exception) {
            return null;
        }
    }

    private APIGatewayV2HTTPResponse httpResponse(int statusCode, AuthResponse authResponse) {
        String body;

        try {
            body = objectMapper.writeValueAsString(authResponse);
        } catch (JsonProcessingException exception) {
            body = "{\"token\":null,\"message\":\"Erro interno.\"}";
            statusCode = 500;
        }

        return APIGatewayV2HTTPResponse.builder()
                .withStatusCode(statusCode)
                .withHeaders(Map.of(CONTENT_TYPE, APPLICATION_JSON))
                .withBody(body)
                .build();
    }
}
