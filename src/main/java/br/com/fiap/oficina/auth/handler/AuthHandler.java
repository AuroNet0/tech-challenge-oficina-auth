package br.com.fiap.oficina.auth.handler;

import br.com.fiap.oficina.auth.model.AuthRequest;
import br.com.fiap.oficina.auth.model.AuthResponse;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;

public class AuthHandler implements RequestHandler<AuthRequest, AuthResponse> {

    @Override
    public AuthResponse handleRequest(AuthRequest request, Context context) {
        return new AuthResponse(null, "Fluxo de autenticacao ainda nao implementado.");
    }
}
