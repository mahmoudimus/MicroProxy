package io.github.mahmoudimus.quic;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.connection.ClientConfig;
import io.github.mahmoudimus.quic.connection.ServerConfig;
import io.github.mahmoudimus.quic.connection.SessionCache;
import io.github.mahmoudimus.quic.tls.TestCerts;
import io.github.mahmoudimus.quic.tls.Ticketer;
import io.github.mahmoudimus.quic.tls.TlsConfig;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * Resumption and 0-RTT through the blocking API over loopback UDP: a resumed connection, a request
 * sent as 0-RTT data before the handshake completes and served from early data, and one a server
 * with 0-RTT off rejects, which reaches it in 1-RTT all the same.
 */
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class ZeroRttLoopbackTest {

    private static final String ALPN = "microproxy-test";
    private final Ticketer ticketer = Ticketer.create();
    private final List<AutoCloseable> closing = new ArrayList<>();

    @AfterEach
    void close() throws Exception {
        for (int i = closing.size() - 1; i >= 0; i--) {
            closing.get(i).close();
        }
    }

    private QuicServer server(boolean earlyData) throws IOException {
        return server(earlyData, Duration.ZERO);
    }

    /**
     * A server that answers each stream with "early:" or "late:" and what it read. It takes {@code
     * delay} to choose the ALPN protocol, which holds its handshake back so that the client's
     * request surely goes out before it.
     */
    private QuicServer server(boolean earlyData, Duration delay) throws IOException {
        TlsConfig tls = TlsConfig.builder()
                .certificate(TestCerts.CA.issue(TestCerts.KeyType.P256, "localhost"))
                .alpnProtocols(ALPN)
                .alpnSelector(hello -> {
                    try {
                        Thread.sleep(delay);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                    return ALPN;
                })
                .sessionTickets(ticketer)
                .earlyData(earlyData)
                .build();
        QuicServer server = QuicServer.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0),
                ServerConfig.builder(tls).build());
        closing.add(server);
        Thread.ofVirtual().start(() -> {
            while (true) {
                QuicConnection c;
                try {
                    c = server.accept();
                } catch (IOException e) {
                    return;
                }
                Thread.ofVirtual().start(() -> {
                    try {
                        while (true) {
                            QuicStream s = c.acceptStream();
                            Thread.ofVirtual().start(() -> answer(s));
                        }
                    } catch (IOException e) {
                        // the connection ended
                    }
                });
            }
        });
        return server;
    }

    private static void answer(QuicStream s) {
        try (InputStream in = s.getInputStream(); OutputStream out = s.getOutputStream()) {
            byte[] request = in.readAllBytes();
            String tag = s.receivedEarlyData() ? "early:" : "late:";
            out.write(tag.getBytes(StandardCharsets.US_ASCII));
            out.write(request);
        } catch (IOException e) {
            // reset
        }
    }

    private QuicClient client(boolean earlyData) throws IOException {
        TlsConfig tls = TlsConfig.builder()
                .serverName("localhost")
                .trustManager(TestCerts.CA.trustManager())
                .alpnProtocols(ALPN)
                .earlyData(earlyData)
                .build();
        QuicClient client = QuicClient.create(ClientConfig.builder(tls).build());
        closing.add(client);
        return client;
    }

    private static String exchange(QuicConnection c, String request) throws IOException {
        QuicStream s = c.openBidirectionalStream();
        try (OutputStream out = s.getOutputStream()) {
            out.write(request.getBytes(StandardCharsets.US_ASCII));
        }
        return new String(s.getInputStream().readAllBytes(), StandardCharsets.US_ASCII);
    }

    /** A full connection that leaves tickets in the client's cache. */
    private static void prime(QuicClient client, QuicServer server) throws IOException {
        try (QuicConnection c = client.connect(server.localAddress(), "localhost", Duration.ofSeconds(10))) {
            assertFalse(c.isResumed());
            assertEquals("late:hello", exchange(c, "hello"));
        }
    }

    @Test
    void resumes() throws Exception {
        QuicServer server = server(false);
        QuicClient client = client(false);
        prime(client, server);
        try (QuicConnection c = client.connect(server.localAddress(), "localhost", Duration.ofSeconds(10))) {
            assertTrue(c.isResumed());
            assertFalse(c.earlyDataAccepted());
            assertEquals("late:again", exchange(c, "again"));
            assertFalse(c.peerCertificates().isEmpty(), "the certificates of the original session");
        }
    }

    @Test
    void zeroRttRequestIsServedFromEarlyData() throws Exception {
        QuicServer server = server(true, Duration.ofMillis(200));
        QuicClient client = client(true);
        prime(client, server);
        QuicConnection c = client.connectEarly(server.localAddress(), "localhost", Duration.ofSeconds(10));
        assertTrue(c.isZeroRtt(), "returned before the handshake");
        assertFalse(c.isHandshakeComplete());
        assertEquals("early:GET /", exchange(c, "GET /"));
        assertTrue(c.awaitHandshake(Duration.ofSeconds(10)));
        assertTrue(c.earlyDataAccepted());
        assertTrue(c.isResumed());
        assertEquals("late:after", exchange(c, "after"));
        c.close();
    }

    @Test
    void rejectedZeroRttIsSentAgain() throws Exception {
        QuicServer primed = server(true);
        QuicServer server = server(false); // the same ticket key, 0-RTT off
        QuicClient client = client(true);
        prime(client, primed);
        QuicConnection c = client.connectEarly(server.localAddress(), "localhost", Duration.ofSeconds(10));
        assertTrue(c.isZeroRtt());
        assertEquals("late:GET /", exchange(c, "GET /"));
        assertTrue(c.awaitHandshake(Duration.ofSeconds(10)));
        assertFalse(c.earlyDataAccepted());
        assertTrue(c.isResumed());
        c.close();
    }

    @Test
    void withoutATicketConnectEarlyWaitsForTheHandshake() throws Exception {
        QuicServer server = server(true);
        QuicClient client = client(true);
        QuicConnection c = client.connectEarly(server.localAddress(), "localhost", Duration.ofSeconds(10),
                SessionCache.none());
        assertTrue(c.isHandshakeComplete());
        assertFalse(c.isResumed());
        assertNotNull(c.alpn());
        assertEquals("late:x", exchange(c, "x"));
        c.close();
    }
}
