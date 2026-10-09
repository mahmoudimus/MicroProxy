package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.SSLSocket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.microproxy.tls.SelfSignedSslContextSource;

class ProxyProtocolTest {

    private HttpProxyServer proxy;

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.abort();
    }

    @Test
    void acceptedHeaderSetsClientAddressAndIsForwarded() throws Exception {
        AtomicReference<InetSocketAddress> clientAddress = new AtomicReference<>();
        proxy = MicroProxy.bootstrap().withPort(0).withAcceptProxyProtocol(true).withSendProxyProtocol(true)
                .plusActivityTracker(new ActivityTrackerAdapter() {
                    @Override
                    public void clientConnected(FlowContext ctx) {
                        clientAddress.set(ctx.getClientAddress());
                    }
                }).start();
        CompletableFuture<String> received = new CompletableFuture<>();
        try (TestSupport.RawServer origin = TestSupport.rawServer(s -> {
            String head = TestSupport.readUntil(s.getInputStream(), "\r\n\r\n");
            received.complete(head);
            TestSupport.write(s.getOutputStream(), "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        })) {
            String response = TestSupport.rawExchange(proxy.getListenAddress(),
                    "PROXY TCP4 203.0.113.7 198.51.100.1 51234 443\r\n"
                            + "GET http://127.0.0.1:" + origin.port() + "/ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
            assertTrue(response.startsWith("HTTP/1.1 200"), response);
            String head = received.get(5, TimeUnit.SECONDS);
            assertTrue(head.startsWith("PROXY TCP4 203.0.113.7 198.51.100.1 51234 443\r\nGET / HTTP/1.1"), head);
        }
        assertEquals("203.0.113.7", clientAddress.get().getAddress().getHostAddress());
        assertEquals(51234, clientAddress.get().getPort());
    }

    @Test
    void binaryV2HeaderIsAccepted() throws Exception {
        AtomicReference<InetSocketAddress> clientAddress = new AtomicReference<>();
        proxy = MicroProxy.bootstrap().withPort(0).withAcceptProxyProtocol(true)
                .plusActivityTracker(new ActivityTrackerAdapter() {
                    @Override
                    public void clientConnected(FlowContext ctx) {
                        clientAddress.set(ctx.getClientAddress());
                    }
                }).start();
        try (Socket s = new Socket(proxy.getListenAddress().getAddress(), proxy.getListenAddress().getPort())) {
            OutputStream out = s.getOutputStream();
            out.write(new byte[] {0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
                0x21, 0x11, 0x00, 0x0C, (byte) 192, 0, 2, 9, 10, 0, 0, 1, 0x1F, (byte) 0x90, 0x01, (byte) 0xBB});
            out.write("GET /x HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
            out.flush();
            String response = new String(s.getInputStream().readAllBytes(), StandardCharsets.ISO_8859_1);
            assertTrue(response.startsWith("HTTP/1.1 400"), response);
        }
        assertEquals("192.0.2.9", clientAddress.get().getAddress().getHostAddress());
        assertEquals(8080, clientAddress.get().getPort());
    }

    @Test
    void missingHeaderIsRejected() throws Exception {
        proxy = MicroProxy.bootstrap().withPort(0).withAcceptProxyProtocol(true).start();
        String response = TestSupport.rawExchange(proxy.getListenAddress(),
                "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n");
        assertEquals("", response);
    }

    /** An origin that records each connection's bytes up to the end of the first request head. */
    private static TestSupport.RawServer recordingOrigin(CompletableFuture<String> received) {
        return TestSupport.rawServer(s -> {
            received.complete(TestSupport.readUntil(s.getInputStream(), "\r\n\r\n"));
            TestSupport.write(s.getOutputStream(), "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        });
    }

    private static String get(TestSupport.RawServer origin) {
        return "GET http://127.0.0.1:" + origin.port() + "/ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    }

    /** LittleProxy canSendProxyProtocolHeader: send without accept, from the TCP peer's address. */
    @Test
    void sendOnlyHeaderCarriesTheTcpPeer() throws Exception {
        proxy = MicroProxy.bootstrap().withPort(0).withSendProxyProtocol(true).start();
        CompletableFuture<String> received = new CompletableFuture<>();
        try (TestSupport.RawServer origin = recordingOrigin(received);
                Socket s = new Socket(proxy.getListenAddress().getAddress(), proxy.getListenAddress().getPort())) {
            s.setSoTimeout(20_000);
            TestSupport.write(s.getOutputStream(), get(origin));
            String response = new String(s.getInputStream().readAllBytes(), StandardCharsets.ISO_8859_1);
            assertTrue(response.startsWith("HTTP/1.1 200"), response);
            String head = received.get(5, TimeUnit.SECONDS);
            // The destination is the address the client connected to (the proxy), as HAProxy sends it.
            // LittleProxy puts the server's address there instead.
            assertTrue(head.startsWith("PROXY TCP4 127.0.0.1 127.0.0.1 " + s.getLocalPort() + " "
                    + proxy.getListenAddress().getPort() + "\r\nGET / HTTP/1.1\r\n"), head);
        }
    }

    /** LittleProxy canAcceptProxyProtocolHeader: accepting alone forwards nothing. */
    @Test
    void acceptOnlyDoesNotForwardTheHeader() throws Exception {
        proxy = MicroProxy.bootstrap().withPort(0).withAcceptProxyProtocol(true).start();
        CompletableFuture<String> received = new CompletableFuture<>();
        try (TestSupport.RawServer origin = recordingOrigin(received)) {
            String response = TestSupport.rawExchange(proxy.getListenAddress(),
                    "PROXY TCP4 192.168.0.153 192.168.0.154 123 456\r\n" + get(origin));
            assertTrue(response.startsWith("HTTP/1.1 200"), response);
            String head = received.get(5, TimeUnit.SECONDS);
            assertTrue(head.startsWith("GET / HTTP/1.1\r\n"), head);
        }
    }

    /** LittleProxy ProxyToServerConnectionBugTest: an IPv6 client yields a TCP6 header. */
    @Test
    void acceptedTcp6HeaderIsForwardedAsTcp6() throws Exception {
        AtomicReference<InetSocketAddress> clientAddress = new AtomicReference<>();
        proxy = MicroProxy.bootstrap().withPort(0).withAcceptProxyProtocol(true).withSendProxyProtocol(true)
                .withChainProxyManager((req, queue, details) -> {
                    clientAddress.set(details.getClientAddress());
                    queue.add(ChainedProxyAdapter.FALLBACK_TO_DIRECT_CONNECTION);
                }).start();
        CompletableFuture<String> received = new CompletableFuture<>();
        try (TestSupport.RawServer origin = recordingOrigin(received)) {
            String response = TestSupport.rawExchange(proxy.getListenAddress(),
                    "PROXY TCP6 2001:db8::1 2001:db8::2 12345 443\r\n" + get(origin));
            assertTrue(response.startsWith("HTTP/1.1 200"), response);
            String head = received.get(5, TimeUnit.SECONDS);
            assertTrue(head.startsWith("PROXY TCP6 2001:db8:0:0:0:0:0:1 2001:db8:0:0:0:0:0:2 12345 443\r\nGET / "), head);
        }
        // ClientDetails, as the chained proxy manager sees it, carries the PROXY header's source.
        assertEquals("2001:db8:0:0:0:0:0:1", clientAddress.get().getAddress().getHostAddress());
        assertEquals(12345, clientAddress.get().getPort());
    }

    /**
     * LittleProxy ProxyProtocolOrderTest: on a TLS listener the PROXY header comes in cleartext
     * before the TLS handshake (as from an AWS NLB).
     */
    @Test
    void headerIsReadBeforeTlsOnATlsListener() throws Exception {
        SelfSignedSslContextSource tls = new SelfSignedSslContextSource();
        proxy = MicroProxy.bootstrap().withPort(0).withSslContextSource(tls)
                .withAcceptProxyProtocol(true).withSendProxyProtocol(true).start();
        CompletableFuture<String> received = new CompletableFuture<>();
        try (TestSupport.RawServer origin = recordingOrigin(received);
                Socket plain = new Socket(proxy.getListenAddress().getAddress(), proxy.getListenAddress().getPort())) {
            plain.setSoTimeout(20_000);
            TestSupport.write(plain.getOutputStream(), "PROXY TCP4 192.168.0.153 192.168.0.154 123 456\r\n");
            SSLSocket secure = (SSLSocket) tls.getSslContext().getSocketFactory()
                    .createSocket(plain, "127.0.0.1", plain.getPort(), true);
            secure.startHandshake();
            TestSupport.write(secure.getOutputStream(), get(origin));
            String response = new String(secure.getInputStream().readAllBytes(), StandardCharsets.ISO_8859_1);
            assertTrue(response.startsWith("HTTP/1.1 200"), response);
            String head = received.get(5, TimeUnit.SECONDS);
            assertTrue(head.startsWith("PROXY TCP4 192.168.0.153 192.168.0.154 123 456\r\nGET / "), head);
        }
    }

    /** LittleProxy ProxyProtocolWrongOrderTest: a PROXY header sent inside TLS is not accepted. */
    @Test
    void headerInsideTlsIsRejected() throws Exception {
        SelfSignedSslContextSource tls = new SelfSignedSslContextSource();
        proxy = MicroProxy.bootstrap().withPort(0).withSslContextSource(tls)
                .withAcceptProxyProtocol(true).withSendProxyProtocol(true).start();
        AtomicInteger originConnections = new AtomicInteger();
        try (TestSupport.RawServer origin = TestSupport.rawServer(s -> originConnections.incrementAndGet());
                Socket plain = new Socket(proxy.getListenAddress().getAddress(), proxy.getListenAddress().getPort())) {
            plain.setSoTimeout(20_000);
            SSLSocket secure = (SSLSocket) tls.getSslContext().getSocketFactory()
                    .createSocket(plain, "127.0.0.1", plain.getPort(), true);
            // The proxy reads the ClientHello as a (bad) PROXY header and closes the connection.
            assertThrows(java.io.IOException.class, () -> {
                secure.startHandshake();
                TestSupport.write(secure.getOutputStream(),
                        "PROXY TCP4 192.168.0.153 192.168.0.154 123 456\r\n" + get(origin));
                if (secure.getInputStream().read() < 0) throw new java.io.EOFException("closed");
            });
            assertEquals(0, originConnections.get());
        }
    }
}
