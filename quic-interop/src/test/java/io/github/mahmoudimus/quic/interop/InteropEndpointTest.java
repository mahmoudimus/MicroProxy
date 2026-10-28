package io.github.mahmoudimus.quic.interop;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.interfaces.ECPrivateKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.HexFormat;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.CopyOnWriteArrayList;
import io.github.mahmoudimus.quic.CipherSuite;
import io.github.mahmoudimus.quic.QuicConnection;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class InteropEndpointTest {
    @TempDir static Path certificates;
    @TempDir Path temporary;

    @BeforeAll
    static void certificates() throws Exception {
        Path store = certificates.resolve("identity.p12");
        Process keytool = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "keytool").toString(),
                "-genkeypair", "-alias", "server", "-keyalg", "EC", "-groupname", "secp256r1", "-dname", "CN=localhost",
                "-ext", "SAN=DNS:localhost", "-validity", "2", "-keystore", store.toString(),
                "-storetype", "PKCS12", "-storepass", "interop-password", "-keypass", "interop-password", "-noprompt")
                .redirectErrorStream(true).start();
        String output = new String(keytool.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertTrue(keytool.waitFor(15, java.util.concurrent.TimeUnit.SECONDS), output);
        assertEquals(0, keytool.exitValue(), output);
        KeyStore keys = KeyStore.getInstance("PKCS12");
        try (var input = Files.newInputStream(store)) { keys.load(input, "interop-password".toCharArray()); }
        byte[] certificate = keys.getCertificate("server").getEncoded();
        Files.writeString(certificates.resolve("cert.pem"), pem("CERTIFICATE", certificate));
        Files.writeString(certificates.resolve("ca.pem"), pem("CERTIFICATE", certificate));
        ECPrivateKey key = (ECPrivateKey) keys.getKey("server", "interop-password".toCharArray());
        // Exercise the exact SEC1 + EC PARAMETERS format from the runner's certs.sh.
        byte[] scalar = key.getS().toByteArray();
        byte[] sec1 = new byte[51];
        byte[] prefix = {0x30, 0x31, 2, 1, 1, 4, 0x20};
        System.arraycopy(prefix, 0, sec1, 0, prefix.length);
        int copy = Math.min(32, scalar.length);
        System.arraycopy(scalar, scalar.length - copy, sec1, 7 + 32 - copy, copy);
        byte[] parameters = {6, 8, 0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 3, 1, 7};
        sec1[39] = (byte) 0xa0;
        sec1[40] = 10;
        System.arraycopy(parameters, 0, sec1, 41, parameters.length);
        Files.writeString(certificates.resolve("priv.key"), pem("EC PARAMETERS", parameters) + pem("EC PRIVATE KEY", sec1));
        Files.writeString(certificates.resolve("pkcs8.key"), pem("PRIVATE KEY", key.getEncoded()));
        Files.writeString(certificates.resolve("sec1-only.key"), pem("EC PRIVATE KEY", sec1));
    }

    @Test
    void readsRunnerSec1AndPkcs8Keys() throws Exception {
        var expected = ((ECPrivateKey) EndpointCertificates.key(certificates.resolve("pkcs8.key"))).getS();
        assertEquals(expected, ((ECPrivateKey) EndpointCertificates.key(certificates.resolve("priv.key"))).getS());
        assertEquals(expected, ((ECPrivateKey) EndpointCertificates.key(certificates.resolve("sec1-only.key"))).getS());
    }

    @ParameterizedTest
    @ValueSource(strings = {"handshake", "transfer", "retry", "chacha20", "keyupdate", "multiconnect", "resumption", "zerortt", "http3"})
    @Timeout(90)
    @SuppressWarnings("try") // Close explicitly to assert that the accept loop has stopped.
    void endpointTransfersParallelFilesOverRealUdp(String testcase) throws Exception {
        Path www = Files.createDirectory(temporary.resolve("www"));
        Path nested = Files.createDirectory(www.resolve("nested"));
        byte[] first = data(42, 1_200_123);
        byte[] second = data(43, 500_123);
        Files.write(www.resolve("first"), first);
        Files.write(nested.resolve("second file"), second);
        Map<String, String> serverEnv = environment(testcase.equals("keyupdate") ? "transfer" : testcase, www);
        InteropEndpoint.Options serverOptions = InteropEndpoint.Options.from(serverEnv);
        try (var server = InteropEndpoint.startServer(serverOptions, new InetSocketAddress(InetAddress.getLoopbackAddress(), 0))) {
            var completed = new CopyOnWriteArrayList<QuicConnection>();
            server.server.observe(new QuicConnection.Observer() {
                @Override public void handshakeCompleted(QuicConnection connection, java.time.Duration elapsed) {
                    completed.add(connection);
                }
            });
            Thread acceptor = accept(server);
            Map<String, String> clientEnv = environment(testcase, www);
            int port = server.server.localAddress().getPort();
            clientEnv.put("REQUESTS", "https://localhost:" + port + "/first https://localhost:" + port + "/nested/second%20file");
            assertEquals(0, InteropEndpoint.execute(clientEnv), testcase);
            Path downloads = Path.of(clientEnv.get("DOWNLOADS"));
            assertArrayEquals(first, Files.readAllBytes(downloads.resolve("first")));
            assertArrayEquals(second, Files.readAllBytes(downloads.resolve("nested/second file")));
            assertEquals(testcase.equals("multiconnect") || testcase.equals("resumption") || testcase.equals("zerortt") ? 2 : 1,
                    server.connections.get());
            if (testcase.equals("retry")) assertTrue(server.server.endpointStats().retriesSent() >= 1);
            if (testcase.equals("chacha20")) {
                assertFalse(completed.isEmpty());
                for (QuicConnection connection : completed) assertEquals(CipherSuite.TLS_CHACHA20_POLY1305_SHA256, connection.cipherSuite());
            }
            if (testcase.equals("resumption") || testcase.equals("zerortt")) {
                assertEquals(2, completed.size());
                assertFalse(completed.getFirst().isResumed());
                assertTrue(completed.getLast().isResumed());
                assertEquals(testcase.equals("zerortt"), completed.getLast().earlyDataAccepted());
            }
            if (testcase.equals("keyupdate")) {
                assertTrue(completed.getFirst().stats().keyUpdates() >= 1);
            }
            assertTrue(Files.size(Path.of(clientEnv.get("SSLKEYLOGFILE"))) > 0);
            try (var logs = Files.list(Path.of(clientEnv.get("QLOGDIR")))) {
                Path log = logs.findFirst().orElseThrow();
                assertTrue(Files.readString(log).startsWith("\u001e{\"qlog_version\":\"0.3\""));
            }
            server.close();
            acceptor.join(5000);
            assertFalse(acceptor.isAlive());
        }
    }

    @Test
    @Timeout(30)
    void zeroRttDownloadsTheRunnersFortyLongFilenameRequests() throws Exception {
        Path www = Files.createDirectory(temporary.resolve("www"));
        Map<String, String> env = environment("zerortt", www);
        try (var server = InteropEndpoint.startServer(InteropEndpoint.Options.from(env), new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
                var capture = new DatagramCapture(server.server.localAddress())) {
            accept(server);
            AtomicReference<CipherSuite> cipher = new AtomicReference<>();
            server.server.observe(new QuicConnection.Observer() {
                @Override public void handshakeCompleted(QuicConnection connection, java.time.Duration elapsed) {
                    cipher.set(connection.cipherSuite());
                }
            });
            StringBuilder requests = new StringBuilder();
            for (int i = 0; i < 40; i++) {
                String name = "a".repeat(247) + String.format("%03d", i);
                Files.write(www.resolve(name), data(i, 32));
                if (!requests.isEmpty()) requests.append(' ');
                requests.append("https://localhost:").append(capture.port()).append('/').append(name);
            }
            env.put("REQUESTS", requests.toString());
            assertEquals(0, InteropEndpoint.execute(env));
            assertEquals(2, server.connections.get());
            for (int i = 0; i < 40; i++) {
                String name = "a".repeat(247) + String.format("%03d", i);
                assertArrayEquals(data(i, 32), Files.readAllBytes(Path.of(env.get("DOWNLOADS")).resolve(name)));
            }
            String earlySecret = Files.readAllLines(Path.of(env.get("SSLKEYLOGFILE"))).stream()
                    .filter(line -> line.startsWith("CLIENT_EARLY_TRAFFIC_SECRET ")).findFirst().orElseThrow().split(" ")[2];
            DatagramCapture.Bytes bytes = capture.bytes(cipher.get(), HexFormat.of().parseHex(earlySecret));
            // Count unique STREAM octets decrypted from actual 0-RTT packets, not merely TLS
            // early-data acceptance. The runner permits under 5 KB of client 1-RTT payload.
            assertTrue(bytes.zeroRttStream() >= 39L * 257 * 4 / 5, "early GET bytes: " + bytes);
            assertTrue(bytes.oneRttPackets() <= 5000, "client 1-RTT packet bytes: " + bytes);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"handshake", "http3"})
    @Timeout(30)
    void missingFileFailsAndDoesNotPublishDownload(String testcase) throws Exception {
        Path www = Files.createDirectory(temporary.resolve("www"));
        Map<String, String> env = environment(testcase, www);
        try (var server = InteropEndpoint.startServer(InteropEndpoint.Options.from(env), new InetSocketAddress(InetAddress.getLoopbackAddress(), 0))) {
            accept(server);
            env.put("REQUESTS", "https://localhost:" + server.server.localAddress().getPort() + "/missing");
            assertEquals(1, InteropEndpoint.execute(env));
            assertFalse(Files.exists(Path.of(env.get("DOWNLOADS")).resolve("missing")));
        }
    }

    @Test
    @Timeout(30)
    void unknownCertificateAuthorityIsRejected() throws Exception {
        Path www = Files.createDirectory(temporary.resolve("www"));
        Files.writeString(www.resolve("file"), "content");
        Map<String, String> env = environment("handshake", www);
        // Without the mounted CA, the JDK's default trust store rejects this certificate.
        Path untrusted = Files.createDirectory(temporary.resolve("untrusted"));
        env.put("CERTS", untrusted.toString());
        Map<String, String> serverEnv = environment("handshake", www);
        try (var server = InteropEndpoint.startServer(InteropEndpoint.Options.from(serverEnv), new InetSocketAddress(InetAddress.getLoopbackAddress(), 0))) {
            accept(server);
            env.put("REQUESTS", "https://localhost:" + server.server.localAddress().getPort() + "/file");
            assertEquals(1, InteropEndpoint.execute(env));
            assertFalse(Files.exists(Path.of(env.get("DOWNLOADS")).resolve("file")));
        }
    }

    @Test
    @Timeout(30)
    void certificateHostnameMismatchIsRejected() throws Exception {
        Path www = Files.createDirectory(temporary.resolve("www"));
        Files.writeString(www.resolve("file"), "content");
        Map<String, String> env = environment("handshake", www);
        try (var server = InteropEndpoint.startServer(InteropEndpoint.Options.from(env), new InetSocketAddress("127.0.0.1", 0))) {
            accept(server);
            env.put("REQUESTS", "https://127.0.0.1:" + server.server.localAddress().getPort() + "/file");
            assertEquals(1, InteropEndpoint.execute(env));
            assertFalse(Files.exists(Path.of(env.get("DOWNLOADS")).resolve("file")));
        }
    }

    private Map<String, String> environment(String testcase, Path www) {
        Map<String, String> env = new HashMap<>();
        env.put("TESTCASE", testcase);
        env.put("ROLE", "client");
        env.put("CERTS", certificates.toString());
        env.put("WWW", www.toString());
        env.put("DOWNLOADS", temporary.resolve("downloads").toString());
        env.put("SSLKEYLOGFILE", temporary.resolve(testcase + "-keys.log").toString());
        env.put("QLOGDIR", temporary.resolve(testcase + "-qlog").toString());
        return env;
    }

    private static Thread accept(InteropEndpoint.EndpointServer server) {
        return Thread.ofVirtual().start(() -> {
            try { server.acceptLoop(); }
            catch (IOException expected) { /* server closed by the test */ }
        });
    }

    private static byte[] data(long seed, int size) {
        byte[] bytes = new byte[size];
        new Random(seed).nextBytes(bytes);
        return bytes;
    }

    private static String pem(String type, byte[] der) {
        return "-----BEGIN " + type + "-----\n" + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(der)
                + "\n-----END " + type + "-----\n";
    }
}
