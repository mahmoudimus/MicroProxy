package io.github.mahmoudimus.quic;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.connection.ClientConfig;
import io.github.mahmoudimus.quic.connection.ConnectionError;
import io.github.mahmoudimus.quic.connection.ServerConfig;
import io.github.mahmoudimus.quic.connection.TransportConfig;
import io.github.mahmoudimus.quic.tls.CertifiedKey;
import io.github.mahmoudimus.quic.tls.NamedGroup;
import io.github.mahmoudimus.quic.tls.TestCerts;
import io.github.mahmoudimus.quic.tls.TlsConfig;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Interoperability with aioquic, an independent QUIC implementation, used only as an external peer:
 * its echo client against the Java server and its echo server against the Java client, over every
 * cipher suite and key exchange group, with large transfers, many streams, datagrams, key updates,
 * Retry, QUIC version 2 and closes from either side, and aioquic's HTTP/3 connection against an
 * HTTP/3 server on http3-codec. The peer scripts are test resources.
 *
 * <p>Skipped unless Python 3 with aioquic is available: the interpreter is {@code
 * -Dquic.interop.python}, else {@code $QUIC_INTEROP_PYTHON}, else {@code python3}. To run:
 * {@code python3 -m venv target/aioquic && target/aioquic/bin/pip install aioquic==1.4.0}, then
 * {@code mvn -pl quic -am test -Dtest=AioquicInteropTest -Dsurefire.failIfNoSpecifiedTests=false
 * -Dquic.interop.python=$PWD/target/aioquic/bin/python}.
 */
@Timeout(value = 180, unit = TimeUnit.SECONDS)
class AioquicInteropTest {

    private static final Pattern RESULT = Pattern.compile("^RESULT (\\{.*})$");

    private static String python;
    private static Path script;
    private static Path certFile;
    private static Path keyFile;
    private static Path caFile;
    private static CertifiedKey certified;

    @TempDir
    static Path dir;

    @BeforeAll
    static void findPython() throws Exception {
        python = System.getProperty("quic.interop.python", System.getenv().getOrDefault("QUIC_INTEROP_PYTHON",
                "python3"));
        boolean available = hasAioquic(python);
        if (Boolean.getBoolean("quic.interop.required")) {
            assertTrue(available, python + " with aioquic is required but not available");
        }
        Assumptions.assumeTrue(available, python + " with aioquic is not available");
        script = Path.of(AioquicInteropTest.class.getResource("/interop/echo_server.py").toURI()).getParent();
        certified = TestCerts.CA.issue(TestCerts.KeyType.P256, "localhost");
        certFile = dir.resolve("cert.pem");
        keyFile = dir.resolve("key.pem");
        caFile = dir.resolve("ca.pem");
        StringBuilder chain = new StringBuilder();
        for (X509Certificate c : certified.chain()) {
            chain.append(pem("CERTIFICATE", c.getEncoded()));
        }
        Files.writeString(certFile, chain);
        Files.writeString(keyFile, pem("PRIVATE KEY", certified.privateKey().getEncoded()));
        Files.writeString(caFile, pem("CERTIFICATE", TestCerts.CA.certificate.getEncoded()));
    }

    private static boolean hasAioquic(String python) {
        try {
            Process p = new ProcessBuilder(python, "-c", "import aioquic").redirectErrorStream(true).start();
            p.getInputStream().transferTo(OutputStream.nullOutputStream());
            return p.waitFor(60, TimeUnit.SECONDS) && p.exitValue() == 0;
        } catch (IOException e) {
            return false;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    private static String pem(String type, byte[] der) {
        return "-----BEGIN " + type + "-----\n" + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(der)
                + "\n-----END " + type + "-----\n";
    }

    // ---------------------------------------------------------------------------------------
    // Peers

    /** A running aioquic echo server. */
    private static final class PythonServer implements AutoCloseable {
        final Process process;
        final LinkedBlockingQueue<String> lines = new LinkedBlockingQueue<>();
        final int port;

        PythonServer(String... extra) throws Exception {
            List<String> cmd = new ArrayList<>(List.of(python, script.resolve("echo_server.py").toString(),
                    "--certificate", certFile.toString(), "--private-key", keyFile.toString()));
            cmd.addAll(List.of(extra));
            process = new ProcessBuilder(cmd).redirectError(ProcessBuilder.Redirect.INHERIT).start();
            Thread.ofVirtual().start(() -> {
                try (BufferedReader r = new BufferedReader(new InputStreamReader(process.getInputStream(),
                        StandardCharsets.UTF_8))) {
                    for (String line; (line = r.readLine()) != null; ) {
                        lines.add(line);
                    }
                } catch (IOException e) {
                    // the process ended
                }
            });
            String first = lines.poll(30, TimeUnit.SECONDS);
            assertNotNull(first, "the aioquic server did not start");
            assertTrue(first.startsWith("LISTENING "), first);
            port = Integer.parseInt(first.substring("LISTENING ".length()).trim());
        }

        InetSocketAddress address() {
            return new InetSocketAddress(InetAddress.getLoopbackAddress(), port);
        }

        /** The next line starting with a prefix, skipping others. */
        String await(String prefix) throws InterruptedException {
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(20);
            while (System.nanoTime() < deadline) {
                String line = lines.poll(100, TimeUnit.MILLISECONDS);
                if (line != null && line.startsWith(prefix)) {
                    return line;
                }
            }
            throw new AssertionError("no '" + prefix + "' from the aioquic server");
        }

        @Override
        public void close() throws IOException {
            process.getOutputStream().close(); // the server exits when stdin closes
            try {
                if (!process.waitFor(10, TimeUnit.SECONDS)) {
                    process.destroyForcibly();
                }
            } catch (InterruptedException e) {
                process.destroyForcibly();
                Thread.currentThread().interrupt();
            }
        }
    }

    /** Runs the aioquic echo client to completion and returns its result line. */
    private static String runClient(InetSocketAddress server, String... extra) throws Exception {
        List<String> cmd = new ArrayList<>(List.of(python, script.resolve("echo_client.py").toString(), "127.0.0.1",
                Integer.toString(server.getPort()), "--ca", caFile.toString()));
        cmd.addAll(List.of(extra));
        return run(cmd);
    }

    /** Runs an aioquic peer script to completion and returns its result line. */
    private static String run(List<String> cmd) throws Exception {
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        StringBuilder output = new StringBuilder();
        Thread reader = Thread.ofVirtual().start(() -> {
            try (InputStream in = p.getInputStream()) {
                output.append(new String(in.readAllBytes(), StandardCharsets.UTF_8));
            } catch (IOException e) {
                // ended
            }
        });
        if (!p.waitFor(150, TimeUnit.SECONDS)) {
            p.destroyForcibly();
            throw new AssertionError("the aioquic client hung");
        }
        reader.join();
        for (String line : output.toString().split("\n")) {
            Matcher m = RESULT.matcher(line.trim());
            if (m.matches()) {
                String json = m.group(1);
                assertTrue(json.contains("\"ok\": true"), "aioquic client failed: " + output);
                assertEquals(0, p.exitValue(), output.toString());
                return json;
            }
        }
        throw new AssertionError("no result from the aioquic client: " + output);
    }

    private static String field(String json, String name) {
        Matcher m = Pattern.compile("\"" + name + "\": (\"[^\"]*\"|[0-9.a-z]+)").matcher(json);
        assertTrue(m.find(), name + " in " + json);
        String v = m.group(1);
        return v.startsWith("\"") ? v.substring(1, v.length() - 1) : v;
    }

    // ---------------------------------------------------------------------------------------
    // Java configurations

    private static TransportConfig transport() {
        return TransportConfig.builder().receiveWindow(64 << 20).sendWindow(32 << 20).streamReceiveWindow(8 << 20)
                .build();
    }

    private static ServerConfig javaServer(CipherSuite suite, NamedGroup group, boolean retry) {
        TlsConfig.Builder tls = TlsConfig.builder().certificate(certified).alpnProtocols("microproxy-test");
        if (suite != null) {
            tls.cipherSuites(suite);
        }
        if (group != null) {
            tls.groups(group);
        }
        return ServerConfig.builder(tls.build()).transport(transport()).retry(retry).build();
    }

    private static ClientConfig javaClient(CipherSuite suite, NamedGroup group, QuicVersion version) {
        TlsConfig.Builder tls = TlsConfig.builder().serverName("localhost").trustManager(TestCerts.CA.trustManager())
                .alpnProtocols("microproxy-test");
        if (suite != null) {
            tls.cipherSuites(suite);
        }
        if (group != null) {
            tls.groups(group);
        }
        return ClientConfig.builder(tls.build()).transport(transport()).version(version).build();
    }

    static Stream<Arguments> suitesAndGroups() {
        List<Arguments> out = new ArrayList<>();
        for (CipherSuite s : CipherSuite.values()) {
            for (NamedGroup g : List.of(NamedGroup.X25519, NamedGroup.SECP256R1, NamedGroup.SECP384R1)) {
                out.add(Arguments.of(s, g));
            }
        }
        return out.stream();
    }

    private static String aioquicName(CipherSuite suite) {
        return suite.name().substring("TLS_".length());
    }

    // ---------------------------------------------------------------------------------------
    // Java server, aioquic client

    @ParameterizedTest(name = "{0} {1}")
    @MethodSource("suitesAndGroups")
    void javaServerChoosesSuiteAndGroup(CipherSuite suite, NamedGroup group) throws Exception {
        try (EchoServer server = new EchoServer(javaServer(suite, group, false))) {
            String result = runClient(server.address(), "--streams", "2", "--size", "20000", "--close-code", "7",
                    "--close-reason", "done");
            assertEquals(aioquicName(suite), field(result, "cipher_suite"));
            QuicConnection c = server.accepted.poll(10, TimeUnit.SECONDS);
            assertNotNull(c);
            assertEquals(suite, c.cipherSuite());
            assertEquals(group, c.keyExchangeGroup());
            ConnectionError reason = c.awaitClosed(Duration.ofSeconds(10));
            assertEquals(new ConnectionError(ConnectionError.Kind.APPLICATION_CLOSED, 7, 0, "done"), reason);
            assertTrue(server.errors().isEmpty(), server.errors().toString());
        }
    }

    @Test
    void javaServerLargeTransferManyStreamsDatagramsAndKeyUpdates() throws Exception {
        try (EchoServer server = new EchoServer(javaServer(null, null, false))) {
            String result = runClient(server.address(), "--streams", "8", "--size", "2000000", "--uni-size",
                    "3000000", "--datagrams", "5", "--key-updates", "3");
            assertEquals(Long.toString(8 * 2_000_000L + 3_000_000L), field(result, "bytes"));
            QuicConnection c = server.accepted.poll(10, TimeUnit.SECONDS);
            assertNotNull(c);
            System.out.println("aioquic client -> Java server: " + result + " " + c.stats());
            assertTrue(c.stats().keyUpdates() >= 3, c.stats().toString());
            assertTrue(server.errors().isEmpty(), server.errors().toString());
        }
    }

    @Test
    void javaServerWithRetry() throws Exception {
        try (EchoServer server = new EchoServer(javaServer(null, null, true))) {
            runClient(server.address(), "--streams", "3", "--size", "100000");
        }
    }

    @Test
    void javaServerSpeaksQuicVersion2() throws Exception {
        try (EchoServer server = new EchoServer(javaServer(null, null, false))) {
            String result = runClient(server.address(), "--version", "2", "--streams", "2", "--size", "50000");
            assertEquals(Integer.toString(QuicVersion.V2.wireValue()), field(result, "version"));
            QuicConnection c = server.accepted.poll(10, TimeUnit.SECONDS);
            assertEquals(QuicVersion.V2, c.version());
        }
    }

    @Test
    void javaServerClosesTheConnection() throws Exception {
        try (EchoServer server = new EchoServer(javaServer(null, null, false))) {
            String result = runClient(server.address(), "--expect-server-close", "close-me");
            assertEquals("42", field(result, "close_code"));
            assertEquals("bye", field(result, "close_reason"));
        }
    }

    @Test
    void aioquicHttp3ClientAgainstJavaHttp3Server() throws Exception {
        TlsConfig tls = TlsConfig.builder().certificate(certified).alpnProtocols("h3").build();
        try (Http3TestServer h3 = new Http3TestServer(ServerConfig.builder(tls).transport(transport()).build())) {
            List<String> cmd = List.of(python, script.resolve("h3_client.py").toString(), "127.0.0.1",
                    Integer.toString(h3.server.localAddress().getPort()), "--ca", caFile.toString());
            String result = run(cmd);
            assertEquals("2000000", field(result, "downloaded"));
            assertEquals("1000000", field(result, "echoed"));
            assertEquals("microproxy-quic", field(result, "server"));
            assertTrue(h3.errors().isEmpty(), h3.errors().toString());
        }
    }

    // ---------------------------------------------------------------------------------------
    // aioquic server, Java client

    @ParameterizedTest(name = "{0} {1}")
    @MethodSource("suitesAndGroups")
    void aioquicServerChoosesSuite(CipherSuite suite, NamedGroup group) throws Exception {
        // aioquic takes the client's first key share, so the Java client's group is the one used
        try (PythonServer py = new PythonServer("--cipher-suite", aioquicName(suite));
                QuicClient client = QuicClient.create(javaClient(null, group, QuicVersion.V1))) {
            assertTrue(py.address().getPort() > 0);
            QuicConnection c = client.connect(py.address(), "localhost", Duration.ofSeconds(20));
            assertEquals(suite, c.cipherSuite());
            assertEquals(group, c.keyExchangeGroup());
            byte[] d = LoopbackTest.data(1, 30_000);
            assertArrayEquals(EchoServer.sha256().digest(d), LoopbackTest.echo(c, d));
            assertTrue(py.await("CONNECTED ").endsWith(aioquicName(suite)));
            c.close(9, "bye from java");
            assertEquals("TERMINATED 9 bye from java", py.await("TERMINATED"));
        }
    }

    @Test
    void javaClientLargeTransferManyStreamsDatagramsAndKeyUpdates() throws Exception {
        try (PythonServer py = new PythonServer();
                QuicClient client = QuicClient.create(javaClient(null, null, QuicVersion.V1))) {
            QuicConnection c = client.connect(py.address(), "localhost", Duration.ofSeconds(20));
            long start = System.nanoTime();
            Thread updater = Thread.ofVirtual().start(() -> {
                for (int i = 0; i < 5; i++) {
                    try {
                        Thread.sleep(100);
                    } catch (InterruptedException e) {
                        return;
                    }
                    c.updateKeys();
                }
            });
            try (ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor()) {
                List<Future<byte[]>> echoes = new ArrayList<>();
                List<byte[]> expected = new ArrayList<>();
                for (int i = 0; i < 8; i++) {
                    byte[] d = LoopbackTest.data(i, 2_000_000);
                    expected.add(EchoServer.sha256().digest(d));
                    echoes.add(pool.submit(() -> LoopbackTest.echo(c, d)));
                }
                for (int i = 0; i < 8; i++) {
                    assertArrayEquals(expected.get(i), echoes.get(i).get(), "stream " + i);
                }
            }
            // A unidirectional stream; the digest comes back on one the server opens
            byte[] upload = LoopbackTest.data(77, 3_000_000);
            QuicStream s = c.openUnidirectionalStream();
            try (OutputStream out = s.getOutputStream()) {
                out.write(upload);
            }
            QuicStream reply = c.acceptStream();
            assertArrayEquals(EchoServer.sha256().digest(upload), reply.getInputStream().readAllBytes());
            updater.join();
            double seconds = (System.nanoTime() - start) / 1e9;
            System.out.printf("Java client -> aioquic server: 35 MB in %.2f s, %s%n", seconds, c.stats());
            assertTrue(c.stats().keyUpdates() >= 2, c.stats().toString());
            // Datagrams
            byte[] got = null;
            for (int i = 0; i < 20 && got == null; i++) {
                c.sendDatagram(("dgram " + i).getBytes(StandardCharsets.US_ASCII));
                got = c.receiveDatagram(Duration.ofMillis(300));
            }
            assertNotNull(got, "no datagram echoed");
            c.close(77, "java-bye");
            assertEquals("TERMINATED 77 java-bye", py.await("TERMINATED"));
        }
    }

    @Test
    void aioquicServerClosesTheConnection() throws Exception {
        try (PythonServer py = new PythonServer();
                QuicClient client = QuicClient.create(javaClient(null, null, QuicVersion.V1))) {
            QuicConnection c = client.connect(py.address(), "localhost", Duration.ofSeconds(20));
            QuicStream s = c.openBidirectionalStream();
            try (OutputStream out = s.getOutputStream()) {
                out.write("close-me".getBytes(StandardCharsets.US_ASCII));
            }
            ConnectionError reason = c.awaitClosed(Duration.ofSeconds(10));
            assertEquals(new ConnectionError(ConnectionError.Kind.APPLICATION_CLOSED, 42, 0, "bye"), reason);
        }
    }

    @Test
    void aioquicServerStartsKeyUpdate() throws Exception {
        try (PythonServer py = new PythonServer();
                QuicClient client = QuicClient.create(javaClient(null, null, QuicVersion.V1))) {
            QuicConnection c = client.connect(py.address(), "localhost", Duration.ofSeconds(20));
            long before = c.stats().keyUpdates();
            for (int i = 0; i < 3; i++) {
                QuicStream s = c.openBidirectionalStream();
                try (OutputStream out = s.getOutputStream()) {
                    out.write("key-update".getBytes(StandardCharsets.US_ASCII));
                }
                assertEquals("ok", new String(s.getInputStream().readAllBytes(), StandardCharsets.US_ASCII));
                byte[] d = LoopbackTest.data(i, 200_000);
                assertArrayEquals(EchoServer.sha256().digest(d), LoopbackTest.echo(c, d));
            }
            assertTrue(c.stats().keyUpdates() >= before + 3, c.stats().toString());
            c.close();
        }
    }

    @Test
    void aioquicServerWithRetry() throws Exception {
        try (PythonServer py = new PythonServer("--retry");
                QuicClient client = QuicClient.create(javaClient(null, null, QuicVersion.V1))) {
            QuicConnection c = client.connect(py.address(), "localhost", Duration.ofSeconds(20));
            byte[] d = LoopbackTest.data(5, 100_000);
            assertArrayEquals(EchoServer.sha256().digest(d), LoopbackTest.echo(c, d));
            c.close();
        }
    }

    @Test
    void javaClientSpeaksQuicVersion2() throws Exception {
        try (PythonServer py = new PythonServer();
                QuicClient client = QuicClient.create(javaClient(null, null, QuicVersion.V2))) {
            QuicConnection c = client.connect(py.address(), "localhost", Duration.ofSeconds(20));
            assertEquals(QuicVersion.V2, c.version());
            byte[] d = LoopbackTest.data(6, 100_000);
            assertArrayEquals(EchoServer.sha256().digest(d), LoopbackTest.echo(c, d));
            c.close();
        }
    }
}
