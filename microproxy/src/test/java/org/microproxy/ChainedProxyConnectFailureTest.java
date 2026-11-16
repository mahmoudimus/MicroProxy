package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.ChainTestSupport.always;
import static org.microproxy.ChainTestSupport.connect;
import static org.microproxy.ChainTestSupport.open;
import static org.microproxy.ChainTestSupport.status;

import java.io.IOException;
import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.OptionalInt;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.ProxyFailure.ConnectFailed.Reason;

/**
 * A chained HTTP proxy that does not open the tunnel the proxy's {@code CONNECT} asks for makes a
 * {@link ProxyFailure.ConnectFailed} that says how, as fields rather than only in its message: the
 * status it answered ({@code 407}, {@code 503}), or that it closed or reset the connection before
 * answering. The cause keeps the message it always had. The fakes answer, close or reset right
 * after reading the {@code CONNECT}, or reset as soon as they accept (in a loop: where that reset
 * lands is a race).
 */
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class ChainedProxyConnectFailureTest {

    private final List<AutoCloseable> closeables = new ArrayList<>();
    private final RecordedFlows flows = new RecordedFlows();
    private final List<Throwable> serverFailures = new CopyOnWriteArrayList<>();
    private final List<Throwable> proxyFailures = new CopyOnWriteArrayList<>();

    @AfterEach
    void tearDown() throws Exception {
        for (AutoCloseable c : closeables.reversed()) c.close();
    }

    private InetSocketAddress fake(TestSupport.RawHandler handler) {
        TestSupport.RawServer server = TestSupport.rawServer(handler);
        closeables.add(server);
        return server.address();
    }

    /** A chained proxy that reads the CONNECT and answers it with {@code statusLine}. */
    private InetSocketAddress answering(String statusLine) {
        return fake(s -> {
            TestSupport.readUntil(s.getInputStream(), "\r\n\r\n");
            TestSupport.write(s.getOutputStream(), "HTTP/1.1 " + statusLine + "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            s.shutdownOutput();
            s.getInputStream().readAllBytes();
        });
    }

    /** A chained proxy that reads the CONNECT and ends the connection without answering. */
    private InetSocketAddress ending(boolean reset) {
        return fake(s -> {
            TestSupport.readUntil(s.getInputStream(), "\r\n\r\n");
            if (reset) s.setSoLinger(true, 0);
            s.close();
        });
    }

    /** CONNECTs through a proxy chained to {@code chained}; returns the failure its record has. */
    private ProxyFailure.ConnectFailed connectThrough(InetSocketAddress chained) throws IOException {
        ChainedProxy proxy = new ChainedProxyAdapter() {
            @Override
            public InetSocketAddress getChainedProxyAddress() {
                return chained;
            }

            @Override
            public void connectionFailed(Throwable cause) {
                proxyFailures.add(cause);
            }
        };
        HttpProxyServer server = MicroProxy.bootstrap().withPort(0).withChainProxyManager(always(proxy))
                .plusActivityTracker(flows)
                .plusActivityTracker(new ActivityTrackerAdapter() {
                    @Override
                    public void serverConnectionExceptionCaught(FullFlowContext ctx, Throwable cause) {
                        serverFailures.add(cause);
                    }
                })
                .start();
        closeables.add(server::abort);
        try (Socket s = open(server.getListenAddress())) {
            assertEquals(502, status(connect(s, "origin.test:443")));
        }
        FlowRecord record = flows.await(FlowRecord.Kind.TUNNEL);
        assertEquals(502, record.responseCode());
        assertEquals("proxy_failure:connect_failed", record.responseCodeDetails());
        assertTrue(record.responseFlags().contains(ResponseFlag.UPSTREAM_CONNECTION_FAILURE));
        ProxyFailure.ConnectFailed failure = assertInstanceOf(ProxyFailure.ConnectFailed.class,
                record.failure().orElseThrow());
        // The same exception for the record, the trackers and the chained proxy.
        assertSame(failure.cause(), serverFailures.getLast());
        assertSame(failure.cause(), proxyFailures.getLast());
        return failure;
    }

    @Test
    void a407IsRefusedWithItsStatus() throws Exception {
        ProxyFailure.ConnectFailed failure = connectThrough(answering("407 Proxy Authentication Required"));
        assertEquals(Reason.CHAINED_PROXY_REFUSED, failure.reason());
        assertEquals(OptionalInt.of(407), failure.chainedProxyStatus());
        assertInstanceOf(ConnectException.class, failure.cause());
        assertEquals("chained proxy refused CONNECT: 407 Proxy Authentication Required", failure.cause().getMessage());
        ChainedProxyConnectException typed = assertInstanceOf(ChainedProxyConnectException.class, failure.cause());
        assertEquals(ChainedProxyConnectException.Outcome.REFUSED, typed.outcome());
        assertEquals("chained_proxy_refused", failure.reason().code());
    }

    @Test
    void a503IsRefusedWithItsStatus() throws Exception {
        ProxyFailure.ConnectFailed failure = connectThrough(answering("503 Service Unavailable"));
        assertEquals(Reason.CHAINED_PROXY_REFUSED, failure.reason());
        assertEquals(OptionalInt.of(503), failure.chainedProxyStatus());
        assertEquals("chained proxy refused CONNECT: 503 Service Unavailable", failure.cause().getMessage());
    }

    @Test
    void aCloseBeforeTheAnswer() throws Exception {
        ProxyFailure.ConnectFailed failure = connectThrough(ending(false));
        assertEquals(Reason.CHAINED_PROXY_CLOSED, failure.reason());
        assertEquals(OptionalInt.empty(), failure.chainedProxyStatus());
        assertInstanceOf(ConnectException.class, failure.cause());
        assertEquals("chained proxy refused CONNECT: connection closed", failure.cause().getMessage());
    }

    @Test
    void aResetBeforeTheAnswer() throws Exception {
        ProxyFailure.ConnectFailed failure = connectThrough(ending(true));
        assertEquals(Reason.CHAINED_PROXY_RESET, failure.reason());
        assertEquals(OptionalInt.empty(), failure.chainedProxyStatus());
        // The socket's own exception, with its message, is the cause.
        assertTrue(failure.cause().getMessage().toLowerCase().contains("reset"), failure.cause().getMessage());
        assertInstanceOf(java.net.SocketException.class, failure.cause().getCause());
        assertEquals(failure.cause().getCause().getMessage(), failure.cause().getMessage());
    }

    /**
     * A chained proxy that resets every connection as soon as it accepts it, before reading
     * anything: the reset reaches the proxy while its connect finishes, while it sets the socket's
     * options, while it writes the {@code CONNECT} or while it reads the answer, as the race goes.
     * Each is the chained proxy's reset all the same. {@code -Dmicroproxy.test.resetRuns=N} runs
     * it N times (default 300); the split by where it failed is printed.
     */
    @Test
    void aResetAsSoonAsAcceptedIsAlwaysAReset() throws Exception {
        int runs = Integer.getInteger("microproxy.test.resetRuns", 300);
        InetSocketAddress resetting = fake(s -> {
            s.setSoLinger(true, 0);
            s.close();
        });
        ChainedProxy proxy = new ChainedProxyAdapter() {
            @Override
            public InetSocketAddress getChainedProxyAddress() {
                return resetting;
            }
        };
        HttpProxyServer server = MicroProxy.bootstrap().withPort(0).withChainProxyManager(always(proxy))
                .plusActivityTracker(flows).start();
        closeables.add(server::abort);
        for (int i = 0; i < runs; i++) {
            try (Socket s = open(server.getListenAddress())) {
                assertEquals(502, status(connect(s, "origin.test:443")));
            }
        }
        TestSupport.eventually(runs + " tunnel records",
                () -> flows.records.stream().filter(r -> r.kind() == FlowRecord.Kind.TUNNEL).count() == runs);
        java.util.Map<String, Integer> split = new java.util.TreeMap<>();
        for (FlowRecord r : flows.records) {
            ProxyFailure.ConnectFailed f = (ProxyFailure.ConnectFailed) r.failure().orElseThrow();
            Throwable root = f.cause().getCause() != null ? f.cause().getCause() : f.cause();
            split.merge(f.reason() + " <- " + root.getClass().getSimpleName() + ": " + root.getMessage(), 1, Integer::sum);
        }
        System.out.println("accept-then-reset, " + runs + " runs: " + split);
        assertEquals(java.util.Set.of(Reason.CHAINED_PROXY_RESET),
                flows.records.stream().map(r -> ((ProxyFailure.ConnectFailed) r.failure().orElseThrow()).reason())
                        .collect(java.util.stream.Collectors.toSet()), split.toString());
    }

    @Test
    void theProxyClosingItsOwnSocketIsNoChainedProxyReset() throws Exception {
        theProxyClosingItsOwnSocket(null);
    }

    @Test
    void theProxyClosingItsOwnSocketToATlsChainedProxyIsNoChainedProxyReset() throws Exception {
        org.microproxy.tls.CertificateAuthority ca = org.microproxy.tls.CertificateAuthority.generate("Chained Proxy CA");
        theProxyClosingItsOwnSocket(ca);
    }

    /**
     * A chained proxy (reached over TLS with {@code ca}'s certificate, when not null) reads the
     * CONNECT and never answers, and the proxy closes the socket it is reading the answer from.
     */
    private void theProxyClosingItsOwnSocket(org.microproxy.tls.CertificateAuthority ca) throws Exception {
        java.util.concurrent.CountDownLatch asked = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.CountDownLatch done = new java.util.concurrent.CountDownLatch(1);
        javax.net.ssl.SSLContext tls = ca == null ? null : ca.serverContext("localhost", "127.0.0.1");
        InetSocketAddress silent = fake(s -> {
            Socket peer = s;
            if (tls != null) {
                javax.net.ssl.SSLSocket server = (javax.net.ssl.SSLSocket) tls.getSocketFactory()
                        .createSocket(s, null, s.getPort(), true);
                server.setUseClientMode(false);
                server.startHandshake();
                peer = server;
            }
            TestSupport.readUntil(peer.getInputStream(), "\r\n\r\n");
            asked.countDown();
            done.await(30, java.util.concurrent.TimeUnit.SECONDS);
        });
        closeables.add(done::countDown);
        ChainedProxy proxy = new ChainedProxyAdapter() {
            @Override
            public InetSocketAddress getChainedProxyAddress() {
                return silent;
            }

            @Override
            public boolean requiresEncryption() {
                return ca != null;
            }

            @Override
            public javax.net.ssl.SSLContext getSslContext() {
                return ca == null ? null : ca.clientContext();
            }

            @Override
            public void connectionFailed(Throwable cause) {
                proxyFailures.add(cause);
            }
        };
        HttpProxyServer server = MicroProxy.bootstrap().withPort(0).withChainProxyManager(always(proxy)).start();
        Socket client = open(server.getListenAddress());
        closeables.add(client);
        TestSupport.write(client.getOutputStream(), "CONNECT origin.test:443 HTTP/1.1\r\nHost: origin.test:443\r\n\r\n");
        assertTrue(asked.await(10, java.util.concurrent.TimeUnit.SECONDS), "the chained proxy got the CONNECT");
        // The proxy closes the socket it is reading the answer from: its own doing, not the chained proxy's.
        server.abort();
        TestSupport.eventually("the attempt to fail", () -> !proxyFailures.isEmpty());
        Throwable cause = proxyFailures.getLast();
        assertFalse(cause instanceof ChainedProxyConnectException, String.valueOf(cause));
        assertEquals(Reason.OTHER, Reason.of(cause));
    }

    @Test
    void anUnreachableProxyIsNoChainedProxyAnswer() throws Exception {
        try (Socket refusing = TestSupport.refusingPort()) {
            ProxyFailure.ConnectFailed failure = connectThrough((InetSocketAddress) refusing.getLocalSocketAddress());
            assertEquals(Reason.OTHER, failure.reason());
            assertEquals(OptionalInt.empty(), failure.chainedProxyStatus());
        }
    }
}
