package io.github.mahmoudimus.quic.tls;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import io.github.mahmoudimus.quic.tls.TestCerts.KeyType;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.InstantSource;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The TLS 1.3 client against OpenSSL's {@code s_server}, for what the JDK's server cannot be asked
 * to do: a KeyUpdate that requests one back. Skipped when no OpenSSL 1.1.1 or later is found
 * ({@code $OPENSSL}, then {@code openssl} on the PATH).
 */
class OpenSslInteropTest {

    private static final String HOST = "tls.test";

    @TempDir
    Path dir;

    private Process server;

    @AfterEach
    void stop() {
        if (server != null) server.destroyForcibly();
    }

    private static String openssl() {
        for (String candidate : new String[] {System.getenv("OPENSSL"), "/opt/homebrew/opt/openssl@3/bin/openssl", "openssl"}) {
            if (candidate == null) continue;
            try {
                Process p = new ProcessBuilder(candidate, "version").redirectErrorStream(true).start();
                String v = new String(p.getInputStream().readAllBytes(), StandardCharsets.US_ASCII);
                if (p.waitFor(10, TimeUnit.SECONDS) && (v.startsWith("OpenSSL 3") || v.startsWith("OpenSSL 1.1.1"))) {
                    return candidate;
                }
            } catch (IOException | InterruptedException e) {
                // try the next one
            }
        }
        return null;
    }

    private static String pem(String type, byte[] der) {
        return "-----BEGIN " + type + "-----\n" + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                .encodeToString(der) + "\n-----END " + type + "-----\n";
    }

    private int freePort() throws IOException {
        try (ServerSocket s = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            return s.getLocalPort();
        }
    }

    /** Reads the server's stdout until it contains {@code text}. */
    private static void awaitOutput(InputStream out, ByteArrayOutputStream seen, String text) throws IOException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (!seen.toString(StandardCharsets.UTF_8).contains(text)) {
            if (System.nanoTime() > deadline) throw new IOException("s_server never printed " + text + ": " + seen);
            int b = out.read();
            if (b < 0) throw new IOException("s_server exited: " + seen);
            seen.write(b);
        }
    }

    @Test
    void aKeyUpdateRequestingOneBackIsAnswered() throws Exception {
        String openssl = openssl();
        assumeTrue(openssl != null, "no OpenSSL 1.1.1+ to run s_server");
        CertifiedKey key = TestCerts.CA.issue(KeyType.P256, HOST);
        Path cert = dir.resolve("cert.pem");
        Path pkey = dir.resolve("key.pem");
        Files.writeString(cert, pem("CERTIFICATE", key.chain().get(0).getEncoded()));
        Files.writeString(pkey, pem("PRIVATE KEY", key.privateKey().getEncoded()));
        int port = freePort();
        server = new ProcessBuilder(openssl, "s_server", "-accept", "127.0.0.1:" + port, "-tls1_3",
                "-cert", cert.toString(), "-key", pkey.toString(), "-alpn", "h2")
                .redirectErrorStream(true).start();
        InputStream serverOut = server.getInputStream();
        OutputStream serverIn = server.getOutputStream();
        ByteArrayOutputStream seen = new ByteArrayOutputStream();
        awaitOutput(serverOut, seen, "ACCEPT");

        TlsClientConnection.Config config = new TlsClientConnection.Config(BrowserProfiles.chrome156(),
                TestCerts.CA.trustManager(), null, ClientSessionStore.NONE, Map.of("h2", new byte[0]),
                CertificateDecompressor.ZLIB, new SecureRandom(), InstantSource.system(), 64 * 1024);
        try (Socket plain = new Socket(InetAddress.getLoopbackAddress(), port)) {
            plain.setSoTimeout(10_000);
            TlsClientConnection c = new TlsClientConnection(config, plain.getInputStream(), plain.getOutputStream(),
                    HOST, HOST, List.of("h2"), null);
            c.handshake();
            assertEquals("h2", c.applicationProtocol());
            awaitOutput(serverOut, seen, "CIPHER is");

            // "K": a KeyUpdate with update_requested; then a line under the new keys. s_server takes
            // a read that starts "K\n" as the command alone, so the line goes in a later read.
            serverIn.write("K\n".getBytes(StandardCharsets.US_ASCII));
            serverIn.flush();
            Thread.sleep(500);
            serverIn.write("after update\n".getBytes(StandardCharsets.US_ASCII));
            serverIn.flush();
            ByteArrayOutputStream got = new ByteArrayOutputStream();
            while (!got.toString(StandardCharsets.UTF_8).contains("after update")) {
                byte[] chunk;
                try {
                    chunk = c.read();
                } catch (java.net.SocketTimeoutException e) {
                    while (serverOut.available() > 0) seen.write(serverOut.read());
                    throw new AssertionError("no data after the KeyUpdate; s_server said: " + seen, e);
                }
                if (chunk == null) break;
                got.write(chunk);
            }
            assertTrue(got.toString(StandardCharsets.UTF_8).contains("after update"), got.toString(StandardCharsets.UTF_8));
            assertEquals(1, c.keyUpdatesReceived());

            // the server takes what we send with our updated keys
            byte[] ping = "ping after our update\n".getBytes(StandardCharsets.US_ASCII);
            c.write(ping, 0, ping.length);
            awaitOutput(serverOut, seen, "ping after our update");
        }
    }
}
