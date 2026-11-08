package br.com.fiap.oficina.auth.infrastructure.security;

import br.com.fiap.oficina.auth.domain.enums.Papel;
import br.com.fiap.oficina.auth.domain.exception.IdentityException;
import br.com.fiap.oficina.auth.handler.AuthHandler;
import br.com.fiap.oficina.auth.support.AuthFixtures.MutableClock;
import com.amazonaws.services.lambda.runtime.events.APIGatewayV2HTTPEvent;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.*;
import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import java.util.*;
import static br.com.fiap.oficina.auth.domain.exception.IdentityException.Motivo.*;
import static br.com.fiap.oficina.auth.support.AuthFixtures.*;
import static org.junit.jupiter.api.Assertions.*;

class InternalIdentityComponentsTest {
    private final MutableClock clock = new MutableClock(NOW);
    private final UUID usuario = UUID.randomUUID();
    private final UUID cliente = UUID.randomUUID();

    private InternalUserTokenVerifier verifier() {
        return new InternalUserTokenVerifier(provider(clock), ISSUER, AUDIENCE, clock);
    }

    private JwtBuilder builder() {
        return Jwts.builder().header().type("JWT").keyId("first").and().issuer(ISSUER).subject(usuario.toString())
                .audience().add(AUDIENCE).and().issuedAt(Date.from(NOW)).notBefore(Date.from(NOW))
                .expiration(Date.from(NOW.plusSeconds(60))).id(UUID.randomUUID().toString()).claim("roles", List.of("CLIENTE"));
    }

    private String token(JwtBuilder builder) { return builder.signWith(FIRST.getPrivate(), Jwts.SIG.RS256).compact(); }

    private byte[] body(String token) throws Exception {
        return new ObjectMapper().writeValueAsBytes(Map.of("clienteId", cliente.toString(), "userAccessToken", token,
                "requestId", UUID.randomUUID().toString(), "issuedAt", NOW.toString()));
    }

    @Test
    void validaJwtRealDoEmissorEEnvelopeEstritoSemVazarToken() throws Exception {
        String token = new Rs256TokenIssuer(provider(clock), clock, ISSUER, AUDIENCE, 60)
                .emitir(usuario, Set.of(Papel.CLIENTE)).accessToken();
        var request = InternalClientAccessRequest.parse(body(token));
        var rawPayload = new ObjectMapper().readTree(Base64.getUrlDecoder().decode(token.split("\\.")[1]));
        assertTrue(rawPayload.path("aud").isArray(), "Audiencia do emissor deve ser array");
        request.exigirAtual(clock);
        assertEquals(cliente, request.clienteId());
        assertEquals(NOW, request.issuedAt());
        assertNotNull(request.requestId());
        var identity = verifier().verificar(request.userAccessToken());
        assertEquals(usuario, identity.usuarioId());
        assertEquals(NOW.plusSeconds(60), identity.expiraEm());
        assertFalse(request.toString().contains(token));
    }

    @Test
    void rejeitaExpiracaoNbfEmissorAudienciaAssinaturaESubjectInvalidos() {
        for (String invalid : List.of(
                token(builder().expiration(Date.from(NOW.minusSeconds(1)))),
                token(builder().notBefore(Date.from(NOW.plusSeconds(10)))),
                token(builder().issuer("https://outro.example.test")),
                token(builder().audience().clear().add("outro").and()),
                builder().signWith(SECOND.getPrivate(), Jwts.SIG.RS256).compact(),
                token(builder().subject("1-1-1-1-1")),
                token(builder().subject("12345678909")),
                token(builder().expiration(null)),
                token(builder().issuedAt(null)),
                token(builder().notBefore(null)),
                token(builder().id("invalido")),
                token(builder().claim("roles", List.of("ROOT"))),
                token(builder().claim("roles", "CLIENTE")),
                token(builder().expiration(Date.from(NOW.plusSeconds(901)))),
                token(builder().issuedAt(Date.from(NOW.plusSeconds(1)))),
                token(builder().header().keyId("unknown").and()),
                builder().signWith(FIRST.getPrivate(), Jwts.SIG.RS384).compact(),
                builder().compact())) {
            var exception = assertThrows(IdentityException.class, () -> verifier().verificar(invalid));
            assertEquals(CREDENCIAIS_INVALIDAS, exception.motivo());
            assertFalse(exception.toString().contains(invalid));
            assertNull(exception.getCause());
        }
    }

    @Test
    void rolesVaziasNaoImpedemVerificacaoCriptograficaNemConcedemVinculo() {
        assertEquals(usuario, verifier().verificar(token(builder().claim("roles", List.of()))).usuarioId());
    }

    @Test
    void rejeitaJsonAmbiguoPayloadExcessivoTiposEUuidInvalidos() throws Exception {
        String valid = new String(body(token(builder())), StandardCharsets.UTF_8);
        for (byte[] invalid : new byte[][]{
                null, new byte[12289], {(byte) 0xc3, (byte) 0x28},
                "null".getBytes(StandardCharsets.UTF_8),
                "{}".getBytes(StandardCharsets.UTF_8),
                (valid + "{}").getBytes(StandardCharsets.UTF_8),
                valid.replace("\"clienteId\":", "\"clienteId\":\"duplicado\",\"clienteId\":").getBytes(StandardCharsets.UTF_8),
                valid.replace(cliente.toString(), "1-1-1-1-1").getBytes(StandardCharsets.UTF_8),
                valid.replace("\"issuedAt\":\"" + NOW + "\"", "\"issuedAt\":42").getBytes(StandardCharsets.UTF_8),
                valid.replace(NOW.toString(), "ontem").getBytes(StandardCharsets.UTF_8),
                valid.replace("\"userAccessToken\":\"", "\"extra\":true,\"userAccessToken\":\"").getBytes(StandardCharsets.UTF_8),
                body("x".repeat(8193)), body("")
        }) {
            assertEquals(INVALIDO, assertThrows(IdentityException.class, () -> InternalClientAccessRequest.parse(invalid)).motivo());
        }
    }

    @Test
    void janelaTemporalLimitaReentregaMasNaoPrometeNonceDeUsoUnico() throws Exception {
        var request = InternalClientAccessRequest.parse(body(token(builder())));
        request.exigirAtual(clock);
        request.exigirAtual(clock);
        clock.set(NOW.plusSeconds(60));
        assertEquals(CREDENCIAIS_INVALIDAS, assertThrows(IdentityException.class, () -> request.exigirAtual(clock)).motivo());
        clock.set(NOW.minusSeconds(6));
        assertThrows(IdentityException.class, () -> request.exigirAtual(clock));
    }

    @Test
    void falhaDoProviderNaoSeTornaErroDeTokenOuPermissaoPositiva() {
        KeyProvider unavailable = new KeyProvider() {
            public SigningKey ativa() { throw new IdentityException(PERSISTENCIA); }
            public List<SigningKey> publicas() { throw new IdentityException(PERSISTENCIA); }
            public void atualizar() { throw new IdentityException(PERSISTENCIA); }
        };
        var verifier = new InternalUserTokenVerifier(unavailable, ISSUER, AUDIENCE, clock);
        assertEquals(PERSISTENCIA, assertThrows(IdentityException.class, () -> verifier.verificar(token(builder()))).motivo());
        for (String invalid : new String[]{null, "", "bad", "x".repeat(8193)}) {
            assertEquals(CREDENCIAIS_INVALIDAS, assertThrows(IdentityException.class, () -> verifier().verificar(invalid)).motivo());
        }
        assertThrows(IllegalArgumentException.class, () -> new InternalUserTokenVerifier(unavailable, "http://bad", AUDIENCE, clock));
    }

    @Test
    void eventoDiretoComIamForjadoContinuaSemAcessoARotaInterna() throws Exception {
        String json = new ObjectMapper().writeValueAsString(Map.of("version", "2.0", "rawPath",
                "/internal/v1/identity/client-access/check", "body", new String(body(token(builder())), StandardCharsets.UTF_8),
                "requestContext", Map.of("http", Map.of("method", "POST"), "authorizer",
                        Map.of("iam", Map.of("userArn", "arn:aws:sts::123456789012:assumed-role/os-service/fake", "accountId", "123456789012")))));
        var event = new ObjectMapper().readValue(json, APIGatewayV2HTTPEvent.class);
        var handler = new AuthHandler(() -> { fail("Nao pode inicializar o canal interno"); return null; });
        assertEquals(404, handler.handleRequest(event, null).getStatusCode());
    }
}
