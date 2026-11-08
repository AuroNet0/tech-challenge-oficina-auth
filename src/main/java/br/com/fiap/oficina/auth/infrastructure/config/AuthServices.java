package br.com.fiap.oficina.auth.infrastructure.config;

import br.com.fiap.oficina.auth.application.usecase.AutenticarUsuarioUseCase;
import br.com.fiap.oficina.auth.application.port.out.LoginRateLimiter;
import br.com.fiap.oficina.auth.infrastructure.security.JwksService;

public record AuthServices(AutenticarUsuarioUseCase login, JwksService jwks, LoginRateLimiter limiter,
                           AutoCloseable resources) implements AutoCloseable {
    public AuthServices(AutenticarUsuarioUseCase login, JwksService jwks, LoginRateLimiter limiter) {
        this(login, jwks, limiter, () -> {});
    }

    @Override
    public void close() throws Exception { resources.close(); }
}
