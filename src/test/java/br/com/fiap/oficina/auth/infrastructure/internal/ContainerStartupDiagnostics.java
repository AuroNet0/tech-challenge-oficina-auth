package br.com.fiap.oficina.auth.infrastructure.internal;

import org.testcontainers.containers.GenericContainer;
import java.util.Locale;

final class ContainerStartupDiagnostics {
    private ContainerStartupDiagnostics() {}

    static void start(GenericContainer<?> container, String... passwords) {
        var output = new StringBuffer();
        container.withLogConsumer(frame -> {
            String safe = sanitize(frame.getUtf8String(), passwords);
            synchronized (output) {
                output.append(safe);
                if (output.length() > 16384) { output.delete(0, output.length() - 16384); }
            }
        });
        try {
            container.start();
        } catch (RuntimeException exception) {
            var details = new StringBuilder();
            Throwable cause = exception;
            for (int depth = 0; cause != null && depth < 12; depth++, cause = cause.getCause()) {
                details.append(cause.getClass().getSimpleName()).append(": ").append(cause.getMessage()).append('\n');
            }
            details.append(output);
            String safe = sanitize(details.toString(), passwords);
            throw new IllegalStateException("Container startup failed [" + category(safe) + "]\n" + safe);
        }
    }

    static String sanitize(String text, String... passwords) {
        String result = text;
        for (String password : passwords) {
            if (password != null && !password.isEmpty()) { result = result.replace(password, "[redacted]"); }
        }
        return result.replaceAll("(?i)((?:password|passwd|pwd)\\s*[=:]\\s*)([^\\s,;]+)", "$1[redacted]");
    }

    static String category(String details) {
        String lower = details.toLowerCase(Locale.ROOT);
        if (lower.contains("accessdeniedexception") || lower.contains("permission denied") || lower.contains("eacces")) {
            return "PERMISSION";
        }
        if (lower.contains("sslexception") || lower.contains("sslhandshakeexception") || lower.contains("certificateexception")
                || lower.contains("keystoreexception") || lower.contains("unrecoverablekeyexception")
                || lower.contains("keystore password") || lower.contains("tampered")) {
            return "TLS";
        }
        if (lower.contains("illegalargumentexception") || lower.contains("nosuchfileexception")
                || lower.contains("numberformatexception") || lower.contains("configuracao")) {
            return "CONFIGURATION";
        }
        return "UNKNOWN";
    }
}
