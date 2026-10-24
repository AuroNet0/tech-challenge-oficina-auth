package br.com.fiap.oficina.auth.application.port.out;

public interface PasswordHasher {
    String hash(char[] senha);
    boolean verificar(char[] senha, String hash);
    boolean precisaRehash(String hash);
    String parametros();
}

