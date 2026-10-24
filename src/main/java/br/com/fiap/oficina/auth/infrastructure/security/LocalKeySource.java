package br.com.fiap.oficina.auth.infrastructure.security;

import java.nio.file.*;
import java.util.Map;
import java.util.function.Supplier;

public final class LocalKeySource implements Supplier<String> {
    private final Path path;

    public LocalKeySource(Map<String, String> env) {
        if (!"local".equals(env.get("AUTH_ENVIRONMENT")) || env.containsKey("AWS_LAMBDA_FUNCTION_NAME")) {
            throw new IllegalArgumentException("Chaves locais permitidas apenas fora da Lambda em ambiente local");
        }
        this.path = Path.of(env.getOrDefault("AUTH_LOCAL_KEY_FILE", ""));
        if (!path.isAbsolute()) { throw new IllegalArgumentException("Caminho absoluto de chaves obrigatorio"); }
    }

    @Override
    public String get() {
        try {
            if (Files.size(path) > 65536) { throw KeyDocuments.indisponivel(); }
            return Files.readString(path);
        } catch (Exception exception) {
            throw KeyDocuments.indisponivel();
        }
    }
}
