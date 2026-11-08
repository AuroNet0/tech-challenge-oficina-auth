package br.com.fiap.oficina.auth.infrastructure.internal;

import org.junit.jupiter.api.Test;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class ContainerStartupDiagnosticsTest {
    @Test void removeSenhasExplicitasEPropriedadesSemPerderCategoria() {
        String raw = "JAVA_TOOL_OPTIONS: -Djavax.net.ssl.trustStorePassword=store-secret\n"
                + "AUTH_DB_PASSWORD=db-secret password=other-secret\nAccessDeniedException: /tls/server.p12";
        String safe = ContainerStartupDiagnostics.sanitize(raw, "store-secret", "db-secret", null, "");
        for (String secret : List.of("store-secret", "db-secret", "other-secret")) { assertFalse(safe.contains(secret)); }
        assertTrue(safe.contains("[redacted]"));
        assertTrue(safe.contains("/tls/server.p12"));
        assertEquals("PERMISSION", ContainerStartupDiagnostics.category(safe));
    }

    @Test void distingueTlsConfiguracaoEDiagnosticoDesconhecido() {
        assertEquals("TLS", ContainerStartupDiagnostics.category("UnrecoverableKeyException: invalid key"));
        assertEquals("TLS", ContainerStartupDiagnostics.category("SSLHandshakeException"));
        assertEquals("CONFIGURATION", ContainerStartupDiagnostics.category("IllegalArgumentException: Configuracao ausente"));
        assertEquals("CONFIGURATION", ContainerStartupDiagnostics.category("NoSuchFileException: /tls/server.p12"));
        assertEquals("UNKNOWN", ContainerStartupDiagnostics.category("Container exited with code 1"));
    }
}
