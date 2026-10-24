package br.com.fiap.oficina.auth.application.port.out;

@FunctionalInterface
public interface LoginRateLimiter {
    void exigir(String sourceIp, String email);
}
