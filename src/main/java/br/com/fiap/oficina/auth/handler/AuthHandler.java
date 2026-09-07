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

import java.util.Optional;

public class AuthHandler implements RequestHandler<AuthRequest, AuthResponse> {

    private final CpfValidator cpfValidator;
    private final ClienteRepository clienteRepository;
    private final JwtService jwtService;

    public AuthHandler() {
        this(new CpfValidator(), new JdbcClienteRepository(), new JwtService());
    }

    AuthHandler(CpfValidator cpfValidator, ClienteRepository clienteRepository, JwtService jwtService) {
        this.cpfValidator = cpfValidator;
        this.clienteRepository = clienteRepository;
        this.jwtService = jwtService;
    }

    @Override
    public AuthResponse handleRequest(AuthRequest request, Context context) {
        if (request == null) {
            return new AuthResponse(null, "Requisi\u00e7\u00e3o inv\u00e1lida.");
        }

        if (!cpfValidator.isValid(request.getCpf())) {
            return new AuthResponse(null, "CPF inv\u00e1lido.");
        }

        Optional<ClienteAuth> cliente = clienteRepository.findByCpf(request.getCpf());

        if (cliente.isEmpty()) {
            return new AuthResponse(null, "Cliente n\u00e3o encontrado.");
        }

        if (!cliente.get().isAtivo()) {
            return new AuthResponse(null, "Cliente inativo.");
        }

        String token = jwtService.generateToken(cliente.get());
        return new AuthResponse(token, "Autentica\u00e7\u00e3o realizada com sucesso.");
    }
}
