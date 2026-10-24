package br.com.fiap.oficina.auth.infrastructure.security;

import br.com.fiap.oficina.auth.domain.enums.Papel;
import br.com.fiap.oficina.auth.domain.exception.IdentityException;
import br.com.fiap.oficina.auth.support.AuthFixtures.MutableClock;
import io.jsonwebtoken.*;
import org.junit.jupiter.api.Test;
import java.time.*;
import java.security.*;
import java.security.interfaces.*;
import java.security.spec.*;
import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import static br.com.fiap.oficina.auth.support.AuthFixtures.*;
import static org.junit.jupiter.api.Assertions.*;

public class JwtAndRotationTest {
    private final MutableClock clock = new MutableClock(NOW);

    public static Jws<Claims> verificar(String token, PublicKey key, Instant now) {
        return Jwts.parser().verifyWith(key).requireIssuer(ISSUER).requireAudience(AUDIENCE)
                .clock(() -> Date.from(now)).sig()
                .remove(Jwts.SIG.HS256).remove(Jwts.SIG.HS384).remove(Jwts.SIG.HS512)
                .remove(Jwts.SIG.RS384).remove(Jwts.SIG.RS512)
                .remove(Jwts.SIG.PS256).remove(Jwts.SIG.PS384).remove(Jwts.SIG.PS512)
                .remove(Jwts.SIG.ES256).remove(Jwts.SIG.ES384).remove(Jwts.SIG.ES512)
                .remove(Jwts.SIG.EdDSA).and().build().parseSignedClaims(token);
    }

    public static PublicKey publicaDoJwks(Map<String, Object> jwks, String kid) {
        try {
            var keys = (List<Map<String, String>>) jwks.get("keys");
            var key = keys.stream().filter(value -> value.get("kid").equals(kid)).findFirst().orElseThrow();
            return KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(
                    new BigInteger(1, Base64.getUrlDecoder().decode(key.get("n"))),
                    new BigInteger(1, Base64.getUrlDecoder().decode(key.get("e")))));
        } catch (Exception exception) { throw new IllegalStateException(exception); }
    }

    @Test
    void claimsObrigatoriasRsaPublicaJwksSemDadosPrivadosOuPessoais() {
        var provider = provider(clock);
        var issuer = new Rs256TokenIssuer(provider, clock, ISSUER, AUDIENCE, 900);
        UUID id = UUID.randomUUID();
        var token = issuer.emitir(id, Set.of(Papel.CLIENTE, Papel.MECANICO));
        var jwks = new JwksService(provider).documento();
        var parsed = verificar(token.accessToken(), publicaDoJwks(jwks, "first"), NOW);
        assertEquals("RS256", parsed.getHeader().getAlgorithm());
        assertEquals("JWT", parsed.getHeader().getType());
        assertEquals("first", parsed.getHeader().getKeyId());
        var claims = parsed.getPayload();
        assertEquals(id.toString(), claims.getSubject());
        assertEquals(Set.of(AUDIENCE), claims.getAudience());
        assertEquals(ISSUER, claims.getIssuer());
        assertEquals(Date.from(NOW), claims.getIssuedAt());
        assertEquals(Date.from(NOW), claims.getNotBefore());
        assertEquals(Date.from(NOW.plusSeconds(900)), claims.getExpiration());
        assertEquals(List.of("CLIENTE", "MECANICO"), claims.get("roles"));
        assertNotNull(UUID.fromString(claims.getId()));
        var second = verificar(issuer.emitir(id, Set.of()).accessToken(), FIRST.getPublic(), NOW).getPayload();
        assertNotEquals(claims.getId(), second.getId());
        assertEquals(List.of(), second.get("roles"));
        assertEquals(Set.of("iss", "sub", "aud", "iat", "nbf", "exp", "jti", "roles"), claims.keySet());
        var published = (List<Map<String, String>>) jwks.get("keys");
        assertEquals(Set.of("kty", "kid", "use", "alg", "n", "e"), published.getFirst().keySet());
        assertFalse(jwks.toString().contains("private"));
        assertFalse(provider.ativa().toString().contains("PRIVATE"));
    }

    @Test
    void rejeitaExpiradoAindaNaoValidoAssinaturaErradaHs256ENone() {
        var issuer = new Rs256TokenIssuer(provider(clock), clock, ISSUER, AUDIENCE, 60);
        String token = issuer.emitir(UUID.randomUUID(), Set.of()).accessToken();
        assertThrows(ExpiredJwtException.class, () -> verificar(token, FIRST.getPublic(), NOW.plusSeconds(61)));
        assertThrows(PrematureJwtException.class, () -> verificar(token, FIRST.getPublic(), NOW.minusSeconds(1)));
        assertThrows(JwtException.class, () -> verificar(token, SECOND.getPublic(), NOW));
        String hs256 = Jwts.builder().subject(UUID.randomUUID().toString()).signWith(Jwts.SIG.HS256.key().build()).compact();
        String none = Jwts.builder().subject(UUID.randomUUID().toString()).compact();
        String rs384 = Jwts.builder().subject(UUID.randomUUID().toString()).signWith(FIRST.getPrivate(), Jwts.SIG.RS384).compact();
        for (String invalid : List.of(hs256, none, rs384, token.substring(0, token.lastIndexOf('.') + 1))) {
            assertThrows(JwtException.class, () -> verificar(invalid, FIRST.getPublic(), NOW));
        }
    }

    @Test
    void rotacaoEntreInstanciasConservaChavesAteJanelaSegura() {
        Instant until = NOW.plusSeconds(60);
        var first = key("first", FIRST, until, true);
        var second = key("second", SECOND, NOW.plusSeconds(7200), true);
        var source = new AtomicReference<>(document("first", first, second));
        var instance1 = new RotatingKeyProvider(source::get, clock);
        var instance2 = new RotatingKeyProvider(source::get, clock);
        var issuer1 = new Rs256TokenIssuer(instance1, clock, ISSUER, AUDIENCE, 900);
        var issuer2 = new Rs256TokenIssuer(instance2, clock, ISSUER, AUDIENCE, 900);
        String old = issuer1.emitir(UUID.randomUUID(), Set.of()).accessToken();
        instance2.atualizar();
        source.set(document("second", first, second));
        clock.set(NOW.plusSeconds(30));
        String next = issuer2.emitir(UUID.randomUUID(), Set.of()).accessToken();
        var jwks = new JwksService(instance1).documento();
        assertEquals(2, ((List<?>) jwks.get("keys")).size());
        verificar(old, publicaDoJwks(jwks, "first"), clock.instant());
        verificar(next, publicaDoJwks(jwks, "second"), clock.instant());
        source.set(document("second", second));
        assertThrows(IdentityException.class, instance1::atualizar);
        clock.set(until.plusSeconds(1050));
        instance1.atualizar();
        assertEquals(1, instance1.publicas().size());
        assertThrows(ExpiredJwtException.class, () -> verificar(old, FIRST.getPublic(), clock.instant()));
    }

    @Test
    void recusaConfiguracaoEManifestosInvalidosOuFalhasSemFallback() {
        for (int ttl : new int[]{0, 59, 901}) {
            assertThrows(IllegalArgumentException.class, () -> new Rs256TokenIssuer(provider(clock), clock, ISSUER, AUDIENCE, ttl));
        }
        assertThrows(IllegalArgumentException.class, () -> new Rs256TokenIssuer(provider(clock), clock, "http://unsafe", AUDIENCE, 900));
        assertThrows(IllegalArgumentException.class, () -> new Rs256TokenIssuer(provider(clock), clock, ISSUER, "", 900));
        var valid = key("first", FIRST, NOW.plusSeconds(7200), true);
        for (String invalid : new String[]{null, "", "{}", "{bad", "x".repeat(65537),
                document("missing", valid), document("first", valid, valid), document("first"),
                "{\"activeKid\":\"a\",\"activeKid\":\"b\",\"keys\":[]}"}) {
            assertThrows(IdentityException.class, () -> new RotatingKeyProvider(() -> invalid, clock).ativa());
        }
        var source = new AtomicReference<>(document("first", valid));
        var provider = new RotatingKeyProvider(source::get, clock);
        provider.ativa();
        source.set(document("first", key("first", SECOND, NOW.plusSeconds(7200), true)));
        assertThrows(IdentityException.class, provider::atualizar);
        source.set(null);
        assertThrows(IdentityException.class, () -> new Rs256TokenIssuer(provider, clock, ISSUER, AUDIENCE, 900)
                .emitir(UUID.randomUUID(), Set.of()));
    }

    @Test
    void rejeitaJanelasCurtasChaveFracaSemPrivadaOuExpirada() throws Exception {
        var original = key("first", FIRST, NOW.plusSeconds(3600), true);
        for (var change : List.of(Map.of("kid", "../bad"), Map.of("publishUntil", NOW.toString()),
                Map.of("signFrom", NOW.minusSeconds(4000).toString()), Map.of("publicKey", "invalid"),
                Map.of("privateKey", Base64.getEncoder().encodeToString(SECOND.getPrivate().getEncoded())))) {
            var copy = new HashMap<>(original);
            copy.putAll(change);
            assertThrows(IdentityException.class, () -> new RotatingKeyProvider(() -> document("first", copy), clock).ativa());
        }
        var generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024);
        var weak = key("weak", generator.generateKeyPair(), NOW.plusSeconds(3600), true);
        assertThrows(IdentityException.class, () -> new RotatingKeyProvider(() -> document("weak", weak), clock).ativa());
        var noPrivate = key("first", FIRST, NOW.plusSeconds(3600), false);
        assertThrows(IdentityException.class, () -> new RotatingKeyProvider(() -> document("first", noPrivate), clock).ativa());
        var provider = provider(clock);
        provider.ativa();
        clock.set(NOW.plusSeconds(7200));
        assertThrows(IdentityException.class, provider::ativa);
        assertEquals(1, provider.publicas().size());
        var empty = new KeyProvider() {
            public SigningKey ativa() { throw KeyDocuments.indisponivel(); }
            public List<SigningKey> publicas() { return List.of(); }
            public void atualizar() {}
        };
        assertThrows(IdentityException.class, () -> new JwksService(empty).documento());
    }
}
