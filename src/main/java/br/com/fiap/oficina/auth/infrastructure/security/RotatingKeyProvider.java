package br.com.fiap.oficina.auth.infrastructure.security;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.function.Supplier;

public final class RotatingKeyProvider implements KeyProvider {
    private final Supplier<String> source;
    private final Clock clock;
    private KeyDocuments.Ring ring;
    private Instant refreshAt = Instant.MIN;

    public RotatingKeyProvider(Supplier<String> source, Clock clock) {
        this.source = source;
        this.clock = clock;
    }

    private synchronized KeyDocuments.Ring snapshot() {
        if (ring == null || !clock.instant().isBefore(refreshAt)) { atualizar(); }
        return ring;
    }

    @Override
    public synchronized void atualizar() {
        try {
            var next = KeyDocuments.ler(source.get());
            Instant agora = clock.instant();
            if (ring != null) {
                for (var old : ring.keys().values()) {
                    var replacement = next.keys().get(old.kid());
                    if (agora.isBefore(old.publishUntil()) && (replacement == null
                            || !old.publica().equals(replacement.publica())
                            || replacement.publishUntil().isBefore(old.publishUntil()))) {
                        throw KeyDocuments.indisponivel();
                    }
                }
            }
            ring = next;
            refreshAt = agora.plusSeconds(30);
        } catch (Exception exception) {
            refreshAt = Instant.MIN;
            throw KeyDocuments.indisponivel();
        }
    }

    @Override
    public SigningKey ativa() {
        var current = snapshot();
        var key = current.keys().get(current.active());
        if (!key.assina(clock.instant())) { throw KeyDocuments.indisponivel(); }
        return key;
    }

    @Override
    public List<SigningKey> publicas() {
        return snapshot().keys().values().stream().filter(key -> key.publicada(clock.instant())).toList();
    }
}
