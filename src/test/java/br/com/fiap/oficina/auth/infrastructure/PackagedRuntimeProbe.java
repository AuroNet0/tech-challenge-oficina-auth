package br.com.fiap.oficina.auth.infrastructure;

import br.com.fiap.oficina.auth.handler.AuthHandler;
import br.com.fiap.oficina.auth.infrastructure.config.MigrateIdentity;
import br.com.fiap.oficina.auth.infrastructure.security.Argon2idPasswordHasher;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Arrays;
import static br.com.fiap.oficina.auth.support.AuthFixtures.*;
import static br.com.fiap.oficina.auth.infrastructure.security.JwtAndRotationTest.*;

public final class PackagedRuntimeProbe {
    public static void main(String[] args) throws Exception {
        var handler = new AuthHandler();
        if (handler.handleRequest(null, null).getStatusCode() != 400) {
            throw new IllegalStateException("Handler deveria falhar fechado");
        }
        if (handler.handleRequest(event("POST", "/internal/v1/identity/client-access/check", "{}"), null)
                .getStatusCode() != 404) {
            throw new IllegalStateException("Rota interna deveria permanecer inacessivel");
        }
        Class.forName("br.com.fiap.oficina.auth.application.usecase.VerificarAcessoClienteUseCase");
        var hasher = new Argon2idPasswordHasher();
        char[] senha = "senha-ficticia-probe".toCharArray();
        try {
            if (!hasher.verificar(senha, hasher.hash(senha))) {
                throw new IllegalStateException("Argon2 indisponivel no JAR");
            }
        } finally { Arrays.fill(senha, '\u0000'); }
        MigrateIdentity.main(args);
        var response = handler.handleRequest(event("POST", "/api/v1/auth/login",
                "{\"email\":\"probe@example.test\",\"senha\":\"" + SENHA + "\"}"), null);
        if (response.getStatusCode() != 200) { throw new IllegalStateException("Login no JAR falhou"); }
        var json = new ObjectMapper().readTree(response.getBody());
        var jwksResponse = handler.handleRequest(event("GET", "/.well-known/jwks.json", null), null);
        var jwks = new ObjectMapper().readValue(jwksResponse.getBody(), java.util.Map.class);
        var claims = verificar(json.get("accessToken").asText(), publicaDoJwks(jwks, "first"), java.time.Instant.now()).getPayload();
        if (!java.util.UUID.fromString(claims.getSubject()).toString().equals(claims.getSubject())) {
            throw new IllegalStateException("Subject incorreto");
        }
        System.out.println("PACKAGED_RUNTIME_OK");
    }
}
