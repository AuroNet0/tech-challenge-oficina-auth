package br.com.fiap.oficina.auth.domain.model;

import br.com.fiap.oficina.auth.domain.enums.Papel;
import br.com.fiap.oficina.auth.domain.exception.IdentityException;
import java.time.Instant;
import java.util.*;
import static br.com.fiap.oficina.auth.domain.exception.IdentityException.Motivo.*;

public final class Usuario {
    private final UUID id;
    private final String email;
    private final String nome;
    private final String cpf;
    private final String passwordHash;
    private boolean ativo;
    private final Instant criadoEm;
    private Instant atualizadoEm;
    private final Set<Papel> papeis;
    private final Map<UUID, UsuarioCliente> clientes;

    public Usuario(UUID id, String email, String nome, String cpf, String passwordHash,
                   boolean ativo, Instant criadoEm, Instant atualizadoEm,
                   Set<Papel> papeis, Collection<UsuarioCliente> clientes) {
        this.id = Objects.requireNonNull(id);
        this.email = normalizarEmail(email);
        if (nome == null || nome.isBlank() || nome.strip().length() > 200
                || passwordHash == null || !passwordHash.matches(
                "\\$argon2id\\$v=19\\$m=[0-9]{1,6},t=[0-9]{1,2},p=[0-9]{1,2}\\$[A-Za-z0-9+/]{22}\\$[A-Za-z0-9+/]{43}")) {
            throw new IdentityException(INVALIDO);
        }
        this.nome = nome.strip();
        this.cpf = normalizarCpf(cpf);
        this.passwordHash = passwordHash;
        this.ativo = ativo;
        this.criadoEm = Objects.requireNonNull(criadoEm);
        this.atualizadoEm = Objects.requireNonNull(atualizadoEm);
        if (atualizadoEm.isBefore(criadoEm)) {
            throw new IdentityException(INVALIDO);
        }
        this.papeis = EnumSet.noneOf(Papel.class);
        this.papeis.addAll(papeis);
        this.clientes = new HashMap<>();
        for (UsuarioCliente cliente : clientes) {
            if (!id.equals(cliente.usuarioId()) || !this.papeis.contains(Papel.CLIENTE)) {
                throw new IdentityException(INVALIDO);
            }
            if (this.clientes.putIfAbsent(cliente.clienteId(), cliente) != null) {
                throw new IdentityException(DUPLICADO);
            }
        }
    }

    public static Usuario criar(String email, String nome, String cpf, String hash, Instant agora) {
        return new Usuario(UUID.randomUUID(), email, nome, cpf, hash, true, agora, agora, Set.of(), List.of());
    }

    public static String normalizarEmail(String email) {
        if (email == null) {
            throw new IdentityException(INVALIDO);
        }
        String normalizado = email.strip().toLowerCase(Locale.ROOT);
        if (normalizado.length() > 254 || !normalizado.matches("[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+")) {
            throw new IdentityException(INVALIDO);
        }
        return normalizado;
    }

    public static String normalizarCpf(String cpf) {
        if (cpf == null) {
            return null;
        }
        if (!cpf.matches("[0-9. \\-]+")) {
            throw new IdentityException(INVALIDO);
        }
        String normalizado = cpf.replaceAll("[. \\-]", "");
        if (!normalizado.matches("[0-9]{11}")) {
            throw new IdentityException(INVALIDO);
        }
        return normalizado;
    }

    public void exigirAtivo() {
        if (!ativo) {
            throw new IdentityException(INATIVO);
        }
    }

    public void atribuir(Papel papel, Instant agora) {
        exigirAtivo();
        validarAtualizacao(agora);
        if (papel == null) {
            throw new IdentityException(INVALIDO);
        }
        if (!papeis.add(papel)) {
            throw new IdentityException(DUPLICADO);
        }
        atualizadoEm = agora;
    }

    public void vincular(UUID clienteId, Instant agora) {
        exigirAtivo();
        validarAtualizacao(agora);
        if (!papeis.contains(Papel.CLIENTE)) {
            throw new IdentityException(NAO_AUTORIZADO);
        }
        UsuarioCliente vinculo = new UsuarioCliente(id, clienteId, agora);
        if (clientes.putIfAbsent(clienteId, vinculo) != null) {
            throw new IdentityException(DUPLICADO);
        }
        atualizadoEm = agora;
    }

    public boolean possuiPrivilegio(Papel papel) {
        return ativo && papeis.contains(papel);
    }

    public boolean podeAcessarCliente(UUID clienteId) {
        return possuiPrivilegio(Papel.CLIENTE) && clientes.containsKey(clienteId);
    }

    public void desativar(Instant agora) {
        validarAtualizacao(agora);
        ativo = false;
        atualizadoEm = agora;
    }

    private void validarAtualizacao(Instant agora) {
        if (agora == null || agora.isBefore(atualizadoEm)) {
            throw new IdentityException(INVALIDO);
        }
    }

    public UUID id() { return id; }
    public String email() { return email; }
    public String nome() { return nome; }
    public String cpf() { return cpf; }
    public String passwordHash() { return passwordHash; }
    public boolean ativo() { return ativo; }
    public Instant criadoEm() { return criadoEm; }
    public Instant atualizadoEm() { return atualizadoEm; }
    public Set<Papel> papeis() { return Set.copyOf(papeis); }
    public Collection<UsuarioCliente> clientes() { return List.copyOf(clientes.values()); }

    @Override
    public String toString() {
        return "Usuario[id=" + id + ", ativo=" + ativo + "]";
    }
}
