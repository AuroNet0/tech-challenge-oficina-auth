package br.com.fiap.oficina.auth.infrastructure.internal;

import javax.net.ssl.*;
import javax.security.auth.x500.X500Principal;
import java.nio.file.*;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.*;

public final class InternalTls {
    private final SSLContext context;
    private final List<X509Certificate> certificates;
    private final X500Principal osSubject;

    public InternalTls(Map<String, String> env) throws Exception {
        osSubject = new X500Principal(env.getOrDefault("AUTH_INTERNAL_OS_SUBJECT", "CN=os-service"));
        if (!Arrays.stream(new javax.naming.ldap.LdapName(osSubject.getName()).getRdns().toArray())
                .anyMatch(value -> value.toString().equalsIgnoreCase("CN=os-service"))) {
            throw new IllegalArgumentException("Identidade OS obrigatoria");
        }
        var identity = store(required(env, "AUTH_INTERNAL_KEYSTORE"), required(env, "AUTH_INTERNAL_KEYSTORE_PASSWORD"));
        var trust = store(required(env, "AUTH_INTERNAL_TRUSTSTORE"), required(env, "AUTH_INTERNAL_TRUSTSTORE_PASSWORD"));
        var owned = new ArrayList<X509Certificate>();
        boolean privateKey = false;
        for (var alias : Collections.list(identity.aliases())) {
            if (identity.isKeyEntry(alias)) {
                privateKey = true;
                for (var certificate : identity.getCertificateChain(alias)) { owned.add((X509Certificate) certificate); }
                var usage = ((X509Certificate) identity.getCertificate(alias)).getExtendedKeyUsage();
                if (usage != null && !usage.contains("1.3.6.1.5.5.7.3.1")) {
                    throw new IllegalArgumentException("Certificado servidor obrigatorio");
                }
            }
        }
        if (!privateKey || trust.size() == 0) { throw new IllegalArgumentException("Stores TLS vazios"); }
        certificates = List.copyOf(owned);
        checkValidity();
        var keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        char[] password = required(env, "AUTH_INTERNAL_KEYSTORE_PASSWORD").toCharArray();
        try { keys.init(identity, password); } finally { Arrays.fill(password, '\0'); }
        var managers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        managers.init(trust);
        context = SSLContext.getInstance("TLS");
        context.init(keys.getKeyManagers(), managers.getTrustManagers(), null);
    }

    private static KeyStore store(String path, String secret) throws Exception {
        var store = KeyStore.getInstance("PKCS12");
        char[] password = secret.toCharArray();
        try (var input = Files.newInputStream(Path.of(path))) { store.load(input, password); }
        finally { Arrays.fill(password, '\0'); }
        return store;
    }

    public static String required(Map<String, String> env, String name) {
        String value = env.get(name);
        if (value == null || value.isBlank()) { throw new IllegalArgumentException("Configuracao ausente: " + name); }
        return value;
    }

    public SSLContext context() { return context; }

    public static SSLContext probeContext(Map<String, String> env) throws Exception {
        var trust = store(required(env, "AUTH_INTERNAL_TRUSTSTORE"), required(env, "AUTH_INTERNAL_TRUSTSTORE_PASSWORD"));
        var managers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        managers.init(trust);
        var context = SSLContext.getInstance("TLS");
        context.init(null, managers.getTrustManagers(), null);
        return context;
    }

    public void checkValidity() throws Exception {
        for (var certificate : certificates) { certificate.checkValidity(); }
    }

    public boolean isOs(SSLSession session) throws Exception {
        var chain = session.getPeerCertificates();
        for (var certificate : chain) { ((X509Certificate) certificate).checkValidity(); }
        var leaf = (X509Certificate) chain[0];
        var usage = leaf.getExtendedKeyUsage();
        return leaf.getBasicConstraints() == -1 && usage != null && usage.contains("1.3.6.1.5.5.7.3.2")
                && osSubject.equals(leaf.getSubjectX500Principal());
    }
}
