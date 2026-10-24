package br.com.fiap.oficina.auth.infrastructure.security;

import br.com.fiap.oficina.auth.application.port.out.PasswordHasher;
import br.com.fiap.oficina.auth.domain.exception.IdentityException;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.regex.Pattern;
import static br.com.fiap.oficina.auth.domain.exception.IdentityException.Motivo.INVALIDO;

public final class Argon2idPasswordHasher implements PasswordHasher {
    private static final int MEMORY = 19456;
    private static final int ITERATIONS = 2;
    private static final Pattern FORMAT = Pattern.compile(
            "^\\$argon2id\\$v=19\\$m=([0-9]{1,6}),t=([0-9]{1,2}),p=([0-9]{1,2})\\$([A-Za-z0-9+/]{22})\\$([A-Za-z0-9+/]{43})$");
    private final SecureRandom random = new SecureRandom();

    @Override
    public String hash(char[] senha) {
        if (senha == null || senha.length < 12 || senha.length > 1024) {
            throw new IdentityException(INVALIDO);
        }
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        byte[] derived = derivar(senha, salt, MEMORY, ITERATIONS, 1);
        try {
            return parametros() + "$" + encode(salt) + "$" + encode(derived);
        } finally {
            Arrays.fill(derived, (byte) 0);
        }
    }

    @Override
    public boolean verificar(char[] senha, String hash) {
        if (senha == null || senha.length > 1024 || hash == null) {
            return false;
        }
        var matcher = FORMAT.matcher(hash);
        if (!matcher.matches()) {
            return false;
        }
        int memory = Integer.parseInt(matcher.group(1));
        int iterations = Integer.parseInt(matcher.group(2));
        int parallelism = Integer.parseInt(matcher.group(3));
        if (memory < 8192 || memory > 65536 || iterations < 1 || iterations > 5 || parallelism < 1 || parallelism > 4) {
            return false;
        }
        try {
            byte[] salt = Base64.getDecoder().decode(matcher.group(4));
            byte[] expected = Base64.getDecoder().decode(matcher.group(5));
            byte[] actual = derivar(senha, salt, memory, iterations, parallelism);
            try {
                return MessageDigest.isEqual(expected, actual);
            } finally {
                Arrays.fill(actual, (byte) 0);
                Arrays.fill(expected, (byte) 0);
            }
        } catch (IllegalArgumentException exception) {
            return false;
        }
    }

    @Override
    public boolean precisaRehash(String hash) {
        return hash == null || !FORMAT.matcher(hash).matches() || !hash.startsWith(parametros() + "$");
    }

    @Override
    public String parametros() {
        return "$argon2id$v=19$m=" + MEMORY + ",t=" + ITERATIONS + ",p=1";
    }

    private byte[] derivar(char[] senha, byte[] salt, int memory, int iterations, int parallelism) {
        var parameters = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13).withMemoryAsKB(memory)
                .withIterations(iterations).withParallelism(parallelism).withSalt(salt).build();
        try {
            var generator = new Argon2BytesGenerator();
            generator.init(parameters);
            byte[] result = new byte[32];
            generator.generateBytes(senha, result);
            return result;
        } finally {
            parameters.clear();
        }
    }

    private String encode(byte[] value) {
        return Base64.getEncoder().withoutPadding().encodeToString(value);
    }
}

