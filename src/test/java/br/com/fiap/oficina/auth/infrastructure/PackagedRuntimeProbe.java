package br.com.fiap.oficina.auth.infrastructure;

import br.com.fiap.oficina.auth.handler.AuthHandler;
import br.com.fiap.oficina.auth.infrastructure.config.MigrateIdentity;
import br.com.fiap.oficina.auth.infrastructure.security.Argon2idPasswordHasher;
import java.util.Arrays;

public final class PackagedRuntimeProbe {
    public static void main(String[] args) {
        if (new AuthHandler().handleRequest(null, null).getStatusCode() != 503) {
            throw new IllegalStateException("Handler deveria falhar fechado");
        }
        var hasher = new Argon2idPasswordHasher();
        char[] senha = "senha-ficticia-probe".toCharArray();
        try {
            if (!hasher.verificar(senha, hasher.hash(senha))) {
                throw new IllegalStateException("Argon2 indisponivel no JAR");
            }
        } finally {
            Arrays.fill(senha, '\u0000');
        }
        MigrateIdentity.main(args);
        System.out.println("PACKAGED_RUNTIME_OK");
    }
}
