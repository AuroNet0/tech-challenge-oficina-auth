package integration;

import br.com.fiap.oficina.auth.application.port.out.ProvisioningAuthorization;
import br.com.fiap.oficina.auth.application.usecase.*;
import br.com.fiap.oficina.auth.domain.enums.Papel;
import br.com.fiap.oficina.auth.infrastructure.config.AuthDatabase;
import br.com.fiap.oficina.auth.infrastructure.persistence.jdbc.JdbcIdentityTransaction;
import br.com.fiap.oficina.auth.infrastructure.security.Argon2idPasswordHasher;
import com.fasterxml.jackson.databind.json.JsonMapper;
import java.nio.file.*;
import java.time.Clock;
import java.util.*;

public final class AuthFixture {
    public static void main(String[] args) {
        try { execute(args); }
        catch (Exception exception) {
            String reason = exception instanceof br.com.fiap.oficina.auth.domain.exception.IdentityException identity
                    ? identity.motivo().name() : exception.getClass().getSimpleName();
            System.err.println("AUTH_FIXTURE_FAILED " + reason);
            System.exit(1);
        }
    }

    private static void execute(String[] args) throws Exception {
        var env = System.getenv();
        if (!"local".equals(env.get("AUTH_ENVIRONMENT")) || !env.get("AUTH_DB_NAME").startsWith("e2e_auth_")
                || env.containsKey("AWS_LAMBDA_FUNCTION_NAME")) { throw new IllegalStateException("E2E fixture only"); }
        var json = JsonMapper.builder().build();
        var input = json.readTree(Files.readAllBytes(Path.of("/run/fixture.json")));
        if (!UUID.fromString(input.path("runId").asText()).toString().equals(env.get("E2E_RUN_ID"))) {
            throw new IllegalStateException("Fixture run mismatch");
        }
        var clock = Clock.systemUTC();
        try (var database = AuthDatabase.criar(env)) {
            var transactions = new JdbcIdentityTransaction(database);
            if ("create".equals(args[0])) {
                var users = json.createObjectNode();
                var permitted = new HashSet<UUID>();
                ProvisioningAuthorization authorization = (operation, user, client) -> {
                    if (operation != ProvisioningAuthorization.Operacao.CADASTRAR
                            && !(operation == ProvisioningAuthorization.Operacao.ATRIBUIR_PAPEL && permitted.contains(user))) {
                        throw new SecurityException();
                    }
                };
                for (var entry : input.path("users").properties()) {
                    char[] password = entry.getValue().path("password").asText().toCharArray();
                    try {
                        var created = new CadastrarUsuarioUseCase(transactions, new Argon2idPasswordHasher(), authorization, clock)
                                .executar(entry.getValue().path("email").asText(), "Pessoa ficticia " + entry.getKey(), null, password);
                        permitted.add(created.id());
                        String role = entry.getValue().path("role").asText();
                        if (!role.isEmpty()) { new AtribuirPapelUseCase(transactions, authorization, clock).executar(created.id(), Papel.valueOf(role)); }
                        users.put(entry.getKey(), created.id().toString());
                    } finally { Arrays.fill(password, '\0'); }
                }
                Files.writeString(Path.of("/run/users.json"), json.writeValueAsString(users), StandardOpenOption.CREATE_NEW);
            } else if ("link".equals(args[0])) {
                var users = json.readTree(Files.readString(Path.of("/run/users.json")));
                var state = json.readTree(Files.readString(Path.of("/run/state.json")));
                var links = Map.of(UUID.fromString(users.path("clienteA").asText()), UUID.fromString(state.path("clienteA").asText()),
                        UUID.fromString(users.path("clienteB").asText()), UUID.fromString(state.path("clienteB").asText()));
                ProvisioningAuthorization authorization = (operation, user, client) -> {
                    if (operation != ProvisioningAuthorization.Operacao.VINCULAR_CLIENTE || !Objects.equals(links.get(user), client)) {
                        throw new SecurityException();
                    }
                };
                for (var link : links.entrySet()) {
                    boolean linked = transactions.executar(repository -> repository.buscarPorId(link.getKey())
                            .map(user -> user.podeAcessarCliente(link.getValue())).orElse(false));
                    if (!linked) { new VincularClienteUseCase(transactions, authorization, clock).executar(link.getKey(), link.getValue()); }
                }
            } else { throw new IllegalArgumentException(); }
        }
        System.out.println("AUTH_FIXTURE_OK " + args[0]);
    }
}
