package br.com.fiap.oficina.auth.support;

import br.com.fiap.oficina.auth.infrastructure.security.*;
import br.com.fiap.oficina.auth.domain.model.Usuario;
import br.com.fiap.oficina.auth.application.port.out.*;
import com.amazonaws.services.lambda.runtime.events.APIGatewayV2HTTPEvent;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import java.security.*;
import java.time.*;
import java.util.*;
import java.util.function.Function;

public final class AuthFixtures {
    public static final Instant NOW = Instant.parse("2026-10-24T12:00:00Z");
    public static final String ISSUER = "https://auth.example.test";
    public static final String AUDIENCE = "oficina";
    public static final String SENHA = "senha-ficticia-segura";
    public static final KeyPair FIRST = gerar();
    public static final KeyPair SECOND = gerar();
    private AuthFixtures() {}

    public static KeyPair gerar() {
        try {
            var generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (Exception exception) { throw new IllegalStateException(exception); }
    }

    public static Map<String, Object> key(String kid, KeyPair pair, Instant until, boolean privateKey) {
        var values = new HashMap<String, Object>();
        values.put("kid", kid);
        values.put("publicKey", Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()));
        if (privateKey) { values.put("privateKey", Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded())); }
        values.put("publishFrom", NOW.minusSeconds(3600).toString());
        values.put("signFrom", NOW.minusSeconds(300).toString());
        values.put("signUntil", until.toString());
        values.put("publishUntil", until.plusSeconds(1050).toString());
        return values;
    }

    public static String document(String active, Object... keys) {
        try { return new ObjectMapper().writeValueAsString(Map.of("activeKid", active, "keys", List.of(keys))); }
        catch (Exception exception) { throw new IllegalStateException(exception); }
    }

    public static RotatingKeyProvider provider(Clock clock) {
        String json = document("first", key("first", FIRST, NOW.plusSeconds(7200), true));
        return new RotatingKeyProvider(() -> json, clock);
    }

    public static APIGatewayV2HTTPEvent event(String method, String path, String body) {
        return APIGatewayV2HTTPEvent.builder().withVersion("2.0").withRawPath(path)
                .withHeaders(Map.of("Content-Type", "application/json")).withBody(body)
                .withRequestContext(APIGatewayV2HTTPEvent.RequestContext.builder()
                        .withHttp(APIGatewayV2HTTPEvent.RequestContext.Http.builder()
                                .withMethod(method).withPath(path).withSourceIp("192.0.2.1").build()).build()).build();
    }

    public static String oldHash() {
        var params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13).withMemoryAsKB(8192)
                .withIterations(1).withParallelism(1).withSalt(new byte[16]).build();
        var generator = new Argon2BytesGenerator();
        generator.init(params);
        byte[] bytes = new byte[32];
        generator.generateBytes(SENHA.toCharArray(), bytes);
        return "$argon2id$v=19$m=8192,t=1,p=1$" + Base64.getEncoder().withoutPadding().encodeToString(new byte[16])
                + "$" + Base64.getEncoder().withoutPadding().encodeToString(bytes);
    }

    public static final class MutableClock extends Clock {
        private Instant now;
        public MutableClock(Instant now) { this.now = now; }
        public void set(Instant now) { this.now = now; }
        public ZoneId getZone() { return ZoneOffset.UTC; }
        public Clock withZone(ZoneId zone) { return this; }
        public Instant instant() { return now; }
    }

    public static final class Store implements IdentityTransaction, UsuarioRepository {
        public Usuario usuario;
        public String rehashed;
        public boolean updateSuccess = true;
        public int reads;
        public Store(Usuario usuario) { this.usuario = usuario; }
        public <T> T executar(Function<UsuarioRepository, T> operation) { return operation.apply(this); }
        public Optional<Usuario> buscarPorId(UUID id) { return Optional.ofNullable(usuario).filter(value -> value.id().equals(id)); }
        public Optional<Usuario> buscarPorEmail(String email) {
            reads++;
            return Optional.ofNullable(usuario).filter(value -> value.email().equals(email));
        }
        public void inserir(Usuario value) { usuario = value; }
        public void salvar(Usuario value) { usuario = value; }
        public boolean atualizarHash(UUID id, String previous, String next, Instant now) { rehashed = next; return updateSuccess; }
    }
}
