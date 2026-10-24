package br.com.fiap.oficina.auth.infrastructure.security;

import br.com.fiap.oficina.auth.application.port.in.AccessToken;
import br.com.fiap.oficina.auth.application.port.out.TokenIssuer;
import br.com.fiap.oficina.auth.domain.enums.Papel;
import io.jsonwebtoken.Jwts;
import java.time.Clock;
import java.time.temporal.ChronoUnit;
import java.util.*;

public final class Rs256TokenIssuer implements TokenIssuer {
    private final KeyProvider keys;
    private final Clock clock;
    private final String issuer;
    private final String audience;
    private final int ttl;

    public Rs256TokenIssuer(KeyProvider keys, Clock clock, String issuer, String audience, int ttl) {
        if (issuer == null || !issuer.matches("https://[^\\s?#]{1,240}")
                || audience == null || !audience.matches("[A-Za-z0-9:/_.-]{1,200}") || ttl < 60 || ttl > 900) {
            throw new IllegalArgumentException("Configuracao JWT invalida");
        }
        this.keys = keys;
        this.clock = clock;
        this.issuer = issuer;
        this.audience = audience;
        this.ttl = ttl;
    }

    @Override
    public AccessToken emitir(UUID usuarioId, Set<Papel> papeis) {
        try {
            var key = keys.ativa();
            var agora = clock.instant().truncatedTo(ChronoUnit.SECONDS);
            String jwt = Jwts.builder().header().type("JWT").keyId(key.kid()).and()
                    .issuer(issuer).subject(usuarioId.toString()).audience().add(audience).and()
                    .issuedAt(Date.from(agora)).notBefore(Date.from(agora))
                    .expiration(Date.from(agora.plusSeconds(ttl))).id(UUID.randomUUID().toString())
                    .claim("roles", papeis.stream().map(Enum::name).sorted().toList())
                    .signWith(key.privada(), Jwts.SIG.RS256).compact();
            return new AccessToken(jwt, "Bearer", ttl);
        } catch (Exception exception) {
            throw KeyDocuments.indisponivel();
        }
    }
}
