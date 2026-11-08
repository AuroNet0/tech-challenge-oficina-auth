package br.com.fiap.oficina.auth.support;

import javax.net.ssl.*;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyStore;
import java.util.*;
import java.util.concurrent.TimeUnit;

public final class TestTls {
    public static final String PASSWORD = "ephemeral-test-password";
    private final Path directory;

    public TestTls(Path directory) throws Exception {
        this.directory = directory;
        keytool("-genkeypair", "-alias", "ca", "-keystore", path("ca.p12"), "-dname", "CN=test-ca",
                "-ext", "bc=ca:true", "-startdate", "-10d", "-validity", "365");
        keytool("-exportcert", "-alias", "ca", "-keystore", path("ca.p12"), "-file", path("ca.cer"));
        keytool("-importcert", "-alias", "ca", "-keystore", path("trust.p12"), "-file", path("ca.cer"), "-noprompt");
        leaf("server", "localhost", false, true);
        leaf("os", "os-service", false, false);
        leaf("billing", "billing-service", false, false);
        leaf("expired", "os-service", true, false);
        keytool("-genkeypair", "-alias", "key", "-keystore", path("unknown.p12"), "-dname", "CN=os-service", "-validity", "30");
    }

    private void leaf(String name, String subject, boolean expired, boolean server) throws Exception {
        keytool("-genkeypair", "-alias", "key", "-keystore", path(name + ".p12"), "-dname", "CN=" + subject, "-validity", "30");
        keytool("-certreq", "-alias", "key", "-keystore", path(name + ".p12"), "-file", path(name + ".csr"));
        keytool("-gencert", "-alias", "ca", "-keystore", path("ca.p12"), "-infile", path(name + ".csr"),
                "-outfile", path(name + ".cer"), "-startdate", expired ? "-3d" : "-1d", "-validity", expired ? "1" : "30",
                "-ext", "ku=digitalSignature,keyEncipherment", "-ext", server ? "eku=serverAuth" : "eku=clientAuth",
                "-ext", "san=dns:localhost");
        keytool("-importcert", "-alias", "ca", "-keystore", path(name + ".p12"), "-file", path("ca.cer"), "-noprompt");
        keytool("-importcert", "-alias", "key", "-keystore", path(name + ".p12"), "-file", path(name + ".cer"), "-noprompt");
    }

    private void keytool(String... args) throws Exception {
        var command = new ArrayList<>(List.of(Path.of(System.getProperty("java.home"), "bin", "keytool").toString()));
        command.addAll(List.of(args));
        command.addAll(List.of("-storepass", PASSWORD, "-storetype", "PKCS12"));
        if (List.of(args).contains("-genkeypair")) { command.addAll(List.of("-keyalg", "RSA", "-keysize", "2048")); }
        Path output = directory.resolve("keytool.log");
        var process = new ProcessBuilder(command).redirectErrorStream(true).redirectOutput(output.toFile()).start();
        if (!process.waitFor(20, TimeUnit.SECONDS)) { process.destroyForcibly(); throw new IllegalStateException("keytool timeout"); }
        if (process.exitValue() != 0) { throw new IllegalStateException(Files.readString(output)); }
    }

    public String path(String name) { return directory.resolve(name).toString(); }

    public Path serverMount() throws Exception {
        Path mount = Files.createTempDirectory(directory, "server-mount-");
        boolean posix = Files.getFileStore(mount).supportsFileAttributeView("posix");
        if (posix) { Files.setPosixFilePermissions(mount, PosixFilePermissions.fromString("rwxr-xr-x")); }
        for (String name : List.of("server.p12", "trust.p12")) {
            Path destination = Files.copy(directory.resolve(name), mount.resolve(name));
            if (posix) { Files.setPosixFilePermissions(destination, PosixFilePermissions.fromString("r--r--r--")); }
        }
        return mount;
    }

    public Map<String, String> environment() {
        return Map.of("AUTH_INTERNAL_KEYSTORE", path("server.p12"), "AUTH_INTERNAL_KEYSTORE_PASSWORD", PASSWORD,
                "AUTH_INTERNAL_TRUSTSTORE", path("trust.p12"), "AUTH_INTERNAL_TRUSTSTORE_PASSWORD", PASSWORD);
    }

    public SSLContext context(String identity) throws Exception {
        var trust = KeyStore.getInstance("PKCS12");
        try (var input = Files.newInputStream(Path.of(path("trust.p12")))) { trust.load(input, PASSWORD.toCharArray()); }
        var trusts = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trusts.init(trust);
        KeyManager[] managers = null;
        if (identity != null) {
            var keys = KeyStore.getInstance("PKCS12");
            try (var input = Files.newInputStream(Path.of(path(identity + ".p12")))) { keys.load(input, PASSWORD.toCharArray()); }
            var factory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            factory.init(keys, PASSWORD.toCharArray());
            var delegate = (X509ExtendedKeyManager) factory.getKeyManagers()[0];
            managers = new KeyManager[]{new X509ExtendedKeyManager() {
                public String chooseClientAlias(String[] types, java.security.Principal[] issuers, java.net.Socket socket) { return "key"; }
                public String chooseEngineClientAlias(String[] types, java.security.Principal[] issuers, SSLEngine engine) { return "key"; }
                public String[] getClientAliases(String type, java.security.Principal[] issuers) { return new String[]{"key"}; }
                public String[] getServerAliases(String type, java.security.Principal[] issuers) { return delegate.getServerAliases(type, issuers); }
                public String chooseServerAlias(String type, java.security.Principal[] issuers, java.net.Socket socket) { return delegate.chooseServerAlias(type, issuers, socket); }
                public java.security.cert.X509Certificate[] getCertificateChain(String alias) { return delegate.getCertificateChain(alias); }
                public java.security.PrivateKey getPrivateKey(String alias) { return delegate.getPrivateKey(alias); }
            }};
        }
        var context = SSLContext.getInstance("TLS");
        context.init(managers, trusts.getTrustManagers(), null);
        return context;
    }
}
