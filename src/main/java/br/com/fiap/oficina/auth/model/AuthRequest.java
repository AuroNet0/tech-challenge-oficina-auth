package br.com.fiap.oficina.auth.model;

public class AuthRequest {

    private String cpf;

    public AuthRequest() {
    }

    public AuthRequest(String cpf) {
        this.cpf = cpf;
    }

    public String getCpf() {
        return cpf;
    }

    public void setCpf(String cpf) {
        this.cpf = cpf;
    }
}
