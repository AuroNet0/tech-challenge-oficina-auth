package br.com.fiap.oficina.auth.infrastructure.security;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;

public final class SigningKey {
    private final String kid;
    private final RSAPublicKey publica;
    private final RSAPrivateKey privada;
    private final Instant publishFrom;
    private final Instant signFrom;
    private final Instant signUntil;
    private final Instant publishUntil;

    public SigningKey(String kid, RSAPublicKey publica, RSAPrivateKey privada, Instant publishFrom,
                      Instant signFrom, Instant signUntil, Instant publishUntil) {
        if (kid == null || !kid.matches("[A-Za-z0-9_-]{1,80}") || publica == null
                || publica.getModulus().bitLength() < 2048 || publica.getModulus().bitLength() > 4096
                || !publica.getPublicExponent().equals(java.math.BigInteger.valueOf(65537))
                || !signFrom.isBefore(signUntil) || publishFrom.isAfter(signFrom.minusSeconds(90))
                || publishUntil.isBefore(signUntil.plusSeconds(1050))
                || (privada != null && !privada.getModulus().equals(publica.getModulus()))) {
            throw KeyDocuments.indisponivel();
        }
        this.kid = kid;
        this.publica = publica;
        this.privada = privada;
        this.publishFrom = publishFrom;
        this.signFrom = signFrom;
        this.signUntil = signUntil;
        this.publishUntil = publishUntil;
    }

    public String kid() { return kid; }
    public RSAPublicKey publica() { return publica; }
    RSAPrivateKey privada() { return privada; }
    public Instant publishUntil() { return publishUntil; }
    public boolean publicada(Instant agora) { return !agora.isBefore(publishFrom) && agora.isBefore(publishUntil); }
    public boolean assina(Instant agora) {
        return privada != null && !agora.isBefore(signFrom) && agora.isBefore(signUntil);
    }

    @Override
    public String toString() { return "SigningKey[kid=" + kid + "]"; }
}
