package br.com.fiap.oficina.auth.infrastructure.persistence.jdbc;

import br.com.fiap.oficina.auth.domain.exception.IdentityException;
import org.junit.jupiter.api.Test;
import org.postgresql.ds.PGSimpleDataSource;
import java.sql.SQLException;
import static br.com.fiap.oficina.auth.domain.exception.IdentityException.Motivo.*;
import static org.junit.jupiter.api.Assertions.*;

class JdbcFailureTest {
    @Test
    void mapeiaSqlSemVazarDetalhes() {
        assertEquals(DUPLICADO, JdbcIdentityTransaction.traduzir(new SQLException("segredo", "23505")).motivo());
        for (String state : new String[]{"40001", "40P01", "55P03"}) {
            assertEquals(CONCORRENCIA, JdbcIdentityTransaction.traduzir(new SQLException("segredo", state)).motivo());
        }
        for (String state : new String[]{null, "08001", "23503"}) {
            var exception = JdbcIdentityTransaction.traduzir(new SQLException("segredo", state));
            assertEquals(PERSISTENCIA, exception.motivo());
            assertFalse(exception.getMessage().contains("segredo"));
            assertNull(exception.getCause());
        }
    }

    @Test
    void conexaoIndisponivelFalhaComErroSeguro() {
        var datasource = new PGSimpleDataSource();
        datasource.setURL("jdbc:postgresql://127.0.0.1:1/inexistente?connectTimeout=1");
        var transaction = new JdbcIdentityTransaction(datasource);
        var exception = assertThrows(IdentityException.class, () -> transaction.executar(repository -> null));
        assertEquals(PERSISTENCIA, exception.motivo());
    }
}

