package br.com.fiap.oficina.auth.infrastructure.security;

import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import java.util.function.Supplier;

public final class SecretsManagerKeySource implements Supplier<String> {
    private final SecretsManagerClient client;
    private final String secretId;

    public SecretsManagerKeySource(SecretsManagerClient client, String secretId) {
        if (secretId == null || secretId.isBlank()) { throw new IllegalArgumentException("Secret ID obrigatorio"); }
        this.client = client;
        this.secretId = secretId;
    }

    @Override
    public String get() {
        try {
            return client.getSecretValue(GetSecretValueRequest.builder()
                    .secretId(secretId).versionStage("AWSCURRENT").build()).secretString();
        } catch (Exception exception) {
            throw KeyDocuments.indisponivel();
        }
    }
}
