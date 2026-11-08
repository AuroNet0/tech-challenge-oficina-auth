package br.com.fiap.oficina.auth.application.port.in;

public record AccessToken(String accessToken, String tokenType, long expiresIn) {
    @Override
    public String toString() {
        return "AccessToken[redacted]";
    }
}
