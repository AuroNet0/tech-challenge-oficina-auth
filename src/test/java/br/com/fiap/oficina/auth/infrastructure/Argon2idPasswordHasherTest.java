package br.com.fiap.oficina.auth.infrastructure;

import br.com.fiap.oficina.auth.infrastructure.security.Argon2idPasswordHasher;
import br.com.fiap.oficina.auth.domain.exception.IdentityException;
import org.junit.jupiter.api.Test;
import java.util.Arrays;
import static org.junit.jupiter.api.Assertions.*;

class Argon2idPasswordHasherTest {
    @Test
    void hashSeguroComSaltAleatorioVerificacaoERehash() {
        var hasher = new Argon2idPasswordHasher();
        char[] senha = "senha-ficticia-de-teste".toCharArray();
        try {
            String hash = hasher.hash(senha);
            assertTrue(hash.startsWith(hasher.parametros()));
            assertNotEquals(hash, hasher.hash(senha));
            assertFalse(hash.contains(new String(senha)));
            assertTrue(hasher.verificar(senha, hash));
            assertFalse(hasher.verificar("outra-senha-ficticia".toCharArray(), hash));
            assertFalse(hasher.precisaRehash(hash));
            assertTrue(hasher.precisaRehash(hash.replace("t=2", "t=1")));
            assertTrue(hasher.precisaRehash(null));
            assertTrue(hasher.precisaRehash("malformado"));
            for (String invalid : new String[]{null, "", "texto", "$argon2id$",
                    hash.replace("m=19456", "m=999999"), hash.replace("t=2", "t=99"),
                    hash.replace("p=1", "p=99"), hash.replace("p=1", "p=0"),
                    hash.replace("m=19456", "m=1")}) {
                assertFalse(hasher.verificar(senha, invalid));
            }
            assertFalse(hasher.verificar(null, hash));
            assertFalse(hasher.verificar(new char[1025], hash));
            assertThrows(IdentityException.class, () -> hasher.hash(null));
            assertThrows(IdentityException.class, () -> hasher.hash(new char[3]));
            assertThrows(IdentityException.class, () -> hasher.hash(new char[1025]));
        } finally {
            Arrays.fill(senha, '\u0000');
        }
    }
}

