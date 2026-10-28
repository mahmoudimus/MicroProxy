package io.github.mahmoudimus.quic.tls;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import io.github.mahmoudimus.quic.tls.TestCerts.KeyType;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.InstantSource;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Encrypted Client Hello against Go's crypto/tls server ({@code ech-server/main.go}, run with
 * {@code go run}): accepted with the Chrome profile, with and without a HelloRetryRequest, and
 * rejected with {@code ech_required} and the server's retry configurations. Skipped when no Go
 * toolchain is found ({@code $GO}, {@code /opt/homebrew/bin/go}, then {@code go} on the PATH).
 */
class EchInteropTest {

    private static final String INNER = "secret.test";
    private static final String PUBLIC = "public.test";

    @TempDir
    Path dir;

    private Process server;
    private final StringBuffer serverOutput = new StringBuffer();
    private byte[] echConfigs;
    private byte[] staleConfigs;
    private int port;

    @AfterEach
    void stop() {
        if (server != null) server.destroyForcibly();
    }

    private static String go() {
        for (String candidate : new String[] {System.getenv("GO"), "/opt/homebrew/bin/go", "/usr/local/go/bin/go", "go"}) {
            if (candidate == null) continue;
            try {
                Process p = new ProcessBuilder(candidate, "version").redirectErrorStream(true).start();
                String v = new String(p.getInputStream().readAllBytes(), StandardCharsets.US_ASCII);
                // EncryptedClientHelloKeys, the server side of ECH, is in Go 1.24 and later
                if (p.waitFor(30, TimeUnit.SECONDS) && v.startsWith("go version go1.") && minor(v) >= 24) return candidate;
            } catch (IOException | InterruptedException e) {
                // try the next one
            }
        }
        return null;
    }

    private static int minor(String version) {
        String rest = version.substring("go version go1.".length());
        int end = 0;
        while (end < rest.length() && Character.isDigit(rest.charAt(end))) end++;
        return end == 0 ? 0 : Integer.parseInt(rest.substring(0, end));
    }

    private static String pem(String type, byte[] der) {
        return "-----BEGIN " + type + "-----\n" + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                .encodeToString(der) + "\n-----END " + type + "-----\n";
    }

    private Path write(String name, String content) throws IOException {
        Path p = dir.resolve(name);
        Files.writeString(p, content);
        return p;
    }

    /** Starts the Go server with {@code extra} flags and reads its configs and port. */
    private void startServer(String... extra) throws Exception {
        String go = go();
        assumeTrue(go != null, "no Go 1.24+ toolchain to run the ECH server");
        Path main = dir.resolve("main.go");
        try (InputStream in = EchInteropTest.class.getResourceAsStream("/ech-server/main.go")) {
            assertNotNull(in, "ech-server/main.go");
            Files.write(main, in.readAllBytes());
        }
        CertifiedKey inner = TestCerts.CA.issue(KeyType.P256, INNER);
        CertifiedKey outer = TestCerts.CA.issue(KeyType.P256, PUBLIC);
        List<String> command = new ArrayList<>(List.of(go, "run", main.toString(),
                "-cert", write("inner.pem", pem("CERTIFICATE", inner.chain().get(0).getEncoded())).toString(),
                "-key", write("inner-key.pem", pem("PRIVATE KEY", inner.privateKey().getEncoded())).toString(),
                "-public-cert", write("outer.pem", pem("CERTIFICATE", outer.chain().get(0).getEncoded())).toString(),
                "-public-key", write("outer-key.pem", pem("PRIVATE KEY", outer.privateKey().getEncoded())).toString(),
                "-public-name", PUBLIC));
        command.addAll(List.of(extra));
        ProcessBuilder pb = new ProcessBuilder(command).directory(dir.toFile()).redirectErrorStream(true);
        pb.environment().put("GOFLAGS", "-mod=mod");
        server = pb.start();
        BufferedReader out = new BufferedReader(new InputStreamReader(server.getInputStream(), StandardCharsets.UTF_8));
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(180);
        while (port == 0) {
            if (System.nanoTime() > deadline) throw new IOException("the ECH server never listened: " + serverOutput);
            String line = out.readLine();
            if (line == null) throw new IOException("the ECH server exited: " + serverOutput);
            serverOutput.append(line).append('\n');
            if (line.startsWith("ECHCONFIGS ")) echConfigs = Base64.getDecoder().decode(line.substring(11));
            if (line.startsWith("STALE ")) staleConfigs = Base64.getDecoder().decode(line.substring(6));
            if (line.startsWith("LISTEN ")) port = Integer.parseInt(line.substring(7).trim());
        }
        Thread drain = new Thread(() -> {
            try {
                for (String line; (line = out.readLine()) != null; ) serverOutput.append(line).append('\n');
            } catch (IOException e) {
                // the server went away
            }
        });
        drain.setDaemon(true);
        drain.start();
    }

    private static TlsClientConnection.Config config(EchConfigProvider provider) {
        return config(provider, ClientSessionStore.NONE);
    }

    private static TlsClientConnection.Config config(EchConfigProvider provider, ClientSessionStore sessions) {
        return new TlsClientConnection.Config(BrowserProfiles.chrome156(), TestCerts.CA.trustManager(), null,
                sessions, Map.of("h2", new byte[0]), CertificateDecompressor.ZLIB, new SecureRandom(),
                InstantSource.system(), 64 * 1024, new Tls12SessionCache(), provider);
    }

    /** Handshakes, reads the server's report, and has a line echoed. */
    private String exchange(TlsClientConnection.Config config, Socket plain) throws IOException {
        return exchange(new TlsClientConnection(config, plain.getInputStream(), plain.getOutputStream(),
                INNER, INNER, List.of("h2", "http/1.1"), INNER + ":" + port));
    }

    private String exchange(TlsClientConnection c) throws IOException {
        c.handshake();
        assertTrue(c.echAccepted(), "ECH accepted");
        String report = readLine(c);
        byte[] ping = "ping over ech\n".getBytes(StandardCharsets.US_ASCII);
        c.write(ping, 0, ping.length);
        assertEquals("echo ping over ech", readLine(c));
        assertEquals(INNER, c.serverName());
        assertEquals("h2", c.applicationProtocol());
        return report;
    }

    private static String readLine(TlsClientConnection c) throws IOException {
        ByteArrayOutputStream got = new ByteArrayOutputStream();
        while (!got.toString(StandardCharsets.UTF_8).contains("\n")) {
            byte[] chunk = c.read();
            if (chunk == null) break;
            got.write(chunk);
        }
        return got.toString(StandardCharsets.UTF_8).strip();
    }

    private Socket connect() throws IOException {
        Socket s = new Socket(InetAddress.getLoopbackAddress(), port);
        s.setSoTimeout(20_000);
        return s;
    }

    @Test
    void theServerAcceptsEchFromTheChromeProfile() throws Exception {
        startServer();
        try (Socket plain = connect()) {
            String report = exchange(config(name -> INNER.equals(name) ? echConfigs : null), plain);
            assertTrue(report.startsWith("sni=" + INNER + " ech=true"), report + "\n" + serverOutput);
        }
    }

    @Test
    void theServerAcceptsEchAfterAHelloRetryRequest() throws Exception {
        startServer("-curves", "23"); // P-256, which Chrome lists but sends no share for
        try (Socket plain = connect()) {
            String report = exchange(config(name -> echConfigs), plain);
            assertEquals("sni=" + INNER + " ech=true group=23", report, serverOutput.toString());
        }
    }

    /** Without a config the profile's GREASE ECH goes, and the second hello's records say TLS 1.2. */
    @Test
    void greaseEchThroughAHelloRetryRequest() throws Exception {
        startServer("-curves", "23");
        try (Socket plain = connect()) {
            TlsClientConnection c = new TlsClientConnection(config(null), plain.getInputStream(),
                    plain.getOutputStream(), INNER, INNER, List.of("h2"), null);
            c.handshake();
            assertFalse(c.echAccepted());
            assertEquals("sni=" + INNER + " ech=false group=23", readLine(c), serverOutput.toString());
        }
    }

    /** A ticket from an ECH connection resumes in the next one's inner hello, never in the outer. */
    @Test
    void resumptionGoesInTheInnerHello() throws Exception {
        startServer();
        ClientSessionStore sessions = new ClientSessionMemoryCache();
        TlsClientConnection.Config config = config(name -> echConfigs, sessions);
        try (Socket plain = connect()) {
            TlsClientConnection c = new TlsClientConnection(config, plain.getInputStream(), plain.getOutputStream(),
                    INNER, INNER, List.of("h2"), INNER + ":" + port);
            assertTrue(exchange(c).startsWith("sni=" + INNER + " ech=true"));
            assertFalse(c.resumed());
        }
        try (Socket plain = connect()) {
            TlsClientConnection c = new TlsClientConnection(config, plain.getInputStream(), plain.getOutputStream(),
                    INNER, INNER, List.of("h2"), INNER + ":" + port);
            assertTrue(exchange(c).startsWith("sni=" + INNER + " ech=true"), serverOutput.toString());
            assertTrue(c.resumed(), "resumed with the ticket of the first connection");
        }
    }

    @Test
    void chaCha20Poly1305Configs() throws Exception {
        startServer("-aeads", "3", "-max-name-length", "0");
        try (Socket plain = connect()) {
            String report = exchange(config(name -> echConfigs), plain);
            assertTrue(report.startsWith("sni=" + INNER + " ech=true"), report);
        }
    }

    @Test
    void aStaleConfigIsRejectedWithTheServersRetryConfigs() throws Exception {
        startServer();
        try (Socket plain = connect()) {
            TlsClientConnection c = new TlsClientConnection(config(name -> staleConfigs), plain.getInputStream(),
                    plain.getOutputStream(), INNER, INNER, List.of("h2"), null);
            TlsClientConnection.TlsAlertException e = assertThrows(TlsClientConnection.TlsAlertException.class, c::handshake);
            assertEquals(TlsAlert.ECH_REQUIRED, e.alert(), e.getMessage());
            assertFalse(e.received());
            assertArrayEquals(echConfigs, e.echRetryConfigs());
            assertFalse(c.echAccepted());
        }
        // the caller may retry with them, on a new connection
        try (Socket plain = connect()) {
            assertTrue(exchange(config(name -> echConfigs), plain).startsWith("sni=" + INNER + " ech=true"));
        }
    }

    @Test
    void aStaleConfigIsRejectedAfterAHelloRetryRequest() throws Exception {
        startServer("-curves", "23");
        try (Socket plain = connect()) {
            TlsClientConnection c = new TlsClientConnection(config(name -> staleConfigs), plain.getInputStream(),
                    plain.getOutputStream(), INNER, INNER, List.of("h2"), null);
            TlsClientConnection.TlsAlertException e = assertThrows(TlsClientConnection.TlsAlertException.class, c::handshake);
            assertEquals(TlsAlert.ECH_REQUIRED, e.alert(), e.getMessage());
            assertArrayEquals(echConfigs, e.echRetryConfigs());
        }
    }

    @Test
    void theSslContextOffersEchAndReportsRejection() throws Exception {
        startServer();
        SSLContext accepted = FingerprintSslContext.builder(BrowserProfiles.chrome156())
                .trustManager(TestCerts.CA.trustManager())
                .echConfigProvider(name -> INNER.equals(name) ? echConfigs : null)
                .build();
        try (SSLSocket s = (SSLSocket) accepted.getSocketFactory().createSocket(connect(), INNER, port, true)) {
            s.startHandshake();
            assertTrue(((FingerprintSocket) s).echAccepted());
            BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream(), StandardCharsets.UTF_8));
            assertTrue(in.readLine().startsWith("sni=" + INNER + " ech=true"));
            OutputStream out = s.getOutputStream();
            out.write("via jsse\n".getBytes(StandardCharsets.US_ASCII));
            out.flush();
            assertEquals("echo via jsse", in.readLine());
        }

        SSLContext stale = FingerprintSslContext.builder(BrowserProfiles.chrome156())
                .trustManager(TestCerts.CA.trustManager())
                .echConfigProvider(name -> staleConfigs)
                .build();
        try (SSLSocket s = (SSLSocket) stale.getSocketFactory().createSocket(connect(), INNER, port, true)) {
            EchRejectedException e = assertThrows(EchRejectedException.class, s::startHandshake);
            assertArrayEquals(echConfigs, e.retryConfigs());
            assertFalse(((FingerprintSocket) s).echAccepted());
        }

        SSLContext grease = FingerprintSslContext.builder(BrowserProfiles.chrome156())
                .trustManager(TestCerts.CA.trustManager())
                .build();
        try (SSLSocket s = (SSLSocket) grease.getSocketFactory().createSocket(connect(), INNER, port, true)) {
            s.startHandshake();
            assertFalse(((FingerprintSocket) s).echAccepted());
            BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream(), StandardCharsets.UTF_8));
            assertTrue(in.readLine().startsWith("sni=" + INNER + " ech=false"));
        }
    }
}
