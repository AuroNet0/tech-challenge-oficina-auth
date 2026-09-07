package br.com.fiap.oficina.auth.model;

public class ClienteAuth {

    private final Long id;
    private final String nome;
    private final String cpf;
    private final boolean ativo;

    public ClienteAuth(Long id, String nome, String cpf, boolean ativo) {
        this.id = id;
        this.nome = nome;
        this.cpf = cpf;
        this.ativo = ativo;
    }

    public Long getId() {
        return id;
    }

    public String getNome() {
        return nome;
    }

    public String getCpf() {
        return cpf;
    }

    public boolean isAtivo() {
        return ativo;
    }
}
