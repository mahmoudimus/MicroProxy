package io.github.mahmoudimus.quic.tls;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.tls.TestCerts.KeyType;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.InstantSource;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * The record that carries the client's fatal alert when it rejects the server's certificate: under
 * TLS 1.3 it is protected with the handshake traffic keys (RFC 8446 section 6, 4.4), under TLS 1.2
 * it is still plaintext. A relay in front of a JDK server records what the client wrote.
 */
class TlsRejectionAlertProtectionTest {

    private static final String HOST = "alert.test";

    private SSLServerSocket server;
    private ServerSocket relay;

    @AfterEach
    void close() throws IOException {
        if (server != null) server.close();
        if (relay != null) relay.close();
    }

    private CompletableFuture<Throwable> serve(String protocol, CertifiedKey key) throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLS");
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("k", key.privateKey(), new char[0], key.chain().toArray(X509Certificate[]::new));
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX");
        kmf.init(ks, new char[0]);
        ctx.init(kmf.getKeyManagers(), new TrustManager[] {TestCerts.CA.trustManager()}, new SecureRandom());
        server = (SSLServerSocket) ctx.getServerSocketFactory().createServerSocket(0, 50, InetAddress.getLoopbackAddress());
        SSLParameters p = server.getSSLParameters();
        p.setProtocols(new String[] {protocol});
        server.setSSLParameters(p);
        CompletableFuture<Throwable> outcome = new CompletableFuture<>();
        Thread.ofVirtual().start(() -> {
            try (SSLSocket s = (SSLSocket) server.accept()) {
                s.setSoTimeout(10_000);
                s.startHandshake();
                s.getInputStream().read();
                outcome.complete(new IOException("server saw no failure"));
            } catch (IOException e) {
                outcome.complete(e);
            }
        });
        return outcome;
    }

    /** Listens on a port that forwards to the server, recording the bytes the client sends. */
    private ByteArrayOutputStream startRelay() throws IOException {
        relay = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
        ByteArrayOutputStream fromClient = new ByteArrayOutputStream();
        Thread.ofVirtual().start(() -> {
            try (Socket c = relay.accept(); Socket s = new Socket(InetAddress.getLoopbackAddress(), server.getLocalPort())) {
                Thread.ofVirtual().start(() -> pump(s, c, null));
                pump(c, s, fromClient);
            } catch (IOException ignored) {
                // closed by the test
            }
        });
        return fromClient;
    }

    private static void pump(Socket from, Socket to, ByteArrayOutputStream tap) {
        try {
            InputStream in = from.getInputStream();
            OutputStream out = to.getOutputStream();
            byte[] buf = new byte[8192];
            for (int n; (n = in.read(buf)) >= 0; ) {
                if (tap != null) {
                    synchronized (tap) {
                        tap.write(buf, 0, n);
                    }
                }
                out.write(buf, 0, n);
                out.flush();
            }
            to.shutdownOutput();
        } catch (IOException ignored) {
            // the other side went away
        }
    }

    private static List<int[]> records(ByteArrayOutputStream tap) {
        byte[] b;
        synchronized (tap) {
            b = tap.toByteArray();
        }
        List<int[]> out = new ArrayList<>();
        for (int i = 0; i + 5 <= b.length; ) {
            int len = (b[i + 3] & 0xff) << 8 | (b[i + 4] & 0xff);
            out.add(new int[] {b[i] & 0xff, len});
            i += 5 + len;
        }
        return out;
    }

    private TlsClientConnection.TlsAlertException rejectedHandshake(String protocol, ByteArrayOutputStream[] tap,
            CompletableFuture<Throwable>[] serverOutcome) throws Exception {
        @SuppressWarnings("unchecked")
        CompletableFuture<Throwable> outcome = serve(protocol, TestCerts.OTHER_CA.issue(KeyType.P256, HOST));
        serverOutcome[0] = outcome;
        tap[0] = startRelay();
        Socket plain = new Socket(InetAddress.getLoopbackAddress(), relay.getLocalPort());
        plain.setSoTimeout(10_000);
        TlsClientConnection.Config config = new TlsClientConnection.Config(BrowserProfiles.chrome156(),
                TestCerts.CA.trustManager(), null, ClientSessionStore.NONE, Map.of("h2", new byte[0]),
                CertificateDecompressor.ZLIB, new SecureRandom(), InstantSource.system(), 64 * 1024,
                new Tls12SessionCache());
        TlsClientConnection c = new TlsClientConnection(config, plain.getInputStream(), plain.getOutputStream(), HOST,
                HOST, List.of("h2", "http/1.1"), HOST + ":443");
        TlsClientConnection.TlsAlertException e =
                assertThrows(TlsClientConnection.TlsAlertException.class, c::handshake);
        assertFalse(e.received());
        plain.close();
        return e;
    }

    @Test
    @SuppressWarnings("unchecked")
    void tls13RejectionAlertIsProtectedUnderTheHandshakeKeys() throws Exception {
        ByteArrayOutputStream[] tap = new ByteArrayOutputStream[1];
        CompletableFuture<Throwable>[] outcome = new CompletableFuture[1];
        TlsClientConnection.TlsAlertException e = rejectedHandshake("TLSv1.3", tap, outcome);
        Throwable seen = outcome[0].get(10, TimeUnit.SECONDS);

        List<int[]> recs = records(tap[0]);
        int[] last = recs.get(recs.size() - 1);
        assertTrue(recs.stream().noneMatch(r -> r[0] == TlsRecordLayer.ALERT),
                "a plaintext alert record was written: " + describe(recs));
        assertEquals(TlsRecordLayer.APPLICATION_DATA, last[0], describe(recs));
        // 2 bytes of alert, 1 of inner content type, 16 of tag
        assertEquals(2 + 1 + 16, last[1], describe(recs));
        // The JDK server decrypted it under the client handshake keys and read the same alert
        assertNotNull(seen);
        assertTrue(seen.getMessage().contains("Received fatal alert: " + TlsAlert.name(e.alert())),
                "server saw: " + seen);
    }

    @Test
    @SuppressWarnings("unchecked")
    void tls12RejectionAlertStaysPlaintext() throws Exception {
        ByteArrayOutputStream[] tap = new ByteArrayOutputStream[1];
        CompletableFuture<Throwable>[] outcome = new CompletableFuture[1];
        TlsClientConnection.TlsAlertException e = rejectedHandshake("TLSv1.2", tap, outcome);
        Throwable seen = outcome[0].get(10, TimeUnit.SECONDS);

        List<int[]> recs = records(tap[0]);
        int[] last = recs.get(recs.size() - 1);
        assertEquals(TlsRecordLayer.ALERT, last[0], describe(recs));
        assertEquals(2, last[1], describe(recs));
        assertTrue(seen.getMessage().contains("Received fatal alert: " + TlsAlert.name(e.alert())),
                "server saw: " + seen);
    }

    private static String describe(List<int[]> recs) {
        StringBuilder sb = new StringBuilder("client records (type,len):");
        for (int[] r : recs) sb.append(" (").append(r[0]).append(',').append(r[1]).append(')');
        return sb.toString();
    }
}
