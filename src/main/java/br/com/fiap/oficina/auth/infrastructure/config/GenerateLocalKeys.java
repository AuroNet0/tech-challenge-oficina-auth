package br.com.fiap.oficina.auth.infrastructure.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPairGenerator;
import java.time.*;
import java.util.*;

public final class GenerateLocalKeys {
    private GenerateLocalKeys() {}

    public static void main(String[] args) throws Exception {
        var env = System.getenv();
        if (!"local".equals(env.get("AUTH_ENVIRONMENT")) || env.containsKey("AWS_LAMBDA_FUNCTION_NAME")) {
            throw new IllegalArgumentException("Geracao de chave disponivel apenas para desenvolvimento local");
        }
        gerar(Path.of(env.getOrDefault("AUTH_LOCAL_KEY_FILE", "")), Clock.systemUTC());
    }

    public static void gerar(Path path, Clock clock) throws Exception {
        if (!path.isAbsolute() || !Files.isDirectory(path.getParent())) {
            throw new IllegalArgumentException("Informe caminho absoluto em diretorio privado existente");
        }
        var generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(3072);
        var pair = generator.generateKeyPair();
        var now = clock.instant();
        String kid = UUID.randomUUID().toString();
        String document = new ObjectMapper().writeValueAsString(Map.of("activeKid", kid, "keys", List.of(Map.of(
                "kid", kid, "publicKey", Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()),
                "privateKey", Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()),
                "publishFrom", now.toString(), "signFrom", now.plusSeconds(90).toString(),
                "signUntil", now.plus(Duration.ofDays(30)).toString(),
                "publishUntil", now.plus(Duration.ofDays(30)).plusSeconds(1050).toString()))));
        if (Files.getFileStore(path.getParent()).supportsFileAttributeView("posix")) {
            Files.createFile(path, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        } else {
            Files.createFile(path);
        }
        Files.writeString(path, document, StandardOpenOption.WRITE);
    }
}
