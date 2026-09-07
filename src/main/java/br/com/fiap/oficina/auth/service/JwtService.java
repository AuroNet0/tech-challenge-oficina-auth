package br.com.fiap.oficina.auth.service;

import br.com.fiap.oficina.auth.model.ClienteAuth;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

public class JwtService {

    private static final String JWT_SECRET_ENV = "JWT_SECRET";
    private static final String CLIENTE_TYPE = "CLIENTE";

    private final String jwtSecret;
    private final Clock clock;

    public JwtService() {
        this(Clock.systemUTC());
    }

    public JwtService(Clock clock) {
        this(System.getenv(JWT_SECRET_ENV), clock);
    }

    public JwtService(String jwtSecret, Clock clock) {
        this.jwtSecret = jwtSecret;
        this.clock = clock;
    }

    public String generateToken(ClienteAuth cliente) {
        if (jwtSecret == null || jwtSecret.isBlank()) {
            throw new ConfigurationException("JWT_SECRET nao configurado.");
        }

        Instant issuedAt = Instant.now(clock);
        Instant expiresAt = issuedAt.plus(1, ChronoUnit.HOURS);
        SecretKey secretKey = buildSigningKey(jwtSecret);

        return Jwts.builder()
                .subject(normalizeCpf(cliente.getCpf()))
                .claim("clienteId", cliente.getId())
                .claim("nome", cliente.getNome())
                .claim("tipo", CLIENTE_TYPE)
                .issuedAt(Date.from(issuedAt))
                .expiration(Date.from(expiresAt))
                .signWith(secretKey, Jwts.SIG.HS256)
                .compact();
    }

    private SecretKey buildSigningKey(String secret) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashedSecret = digest.digest(secret.getBytes(StandardCharsets.UTF_8));
            return Keys.hmacShaKeyFor(hashedSecret);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("Algoritmo SHA-256 indisponivel para assinatura JWT.", exception);
        }
    }

    private String normalizeCpf(String cpf) {
        if (cpf == null) {
            return "";
        }

        return cpf.replaceAll("\\D", "");
    }
}
