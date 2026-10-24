package br.com.fiap.oficina.auth.domain.exception;

public class IdentityException extends RuntimeException {
    public enum Motivo { INVALIDO, DUPLICADO, NAO_ENCONTRADO, NAO_AUTORIZADO, INATIVO, CONCORRENCIA, PERSISTENCIA }

    private final Motivo motivo;

    public IdentityException(Motivo motivo) {
        super("Operacao de identidade recusada: " + motivo.name());
        this.motivo = motivo;
    }

    public Motivo motivo() {
        return motivo;
    }
}

