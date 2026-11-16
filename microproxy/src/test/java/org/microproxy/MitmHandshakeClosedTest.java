package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.ChainTestSupport.always;
import static org.microproxy.ChainTestSupport.connect;
import static org.microproxy.ChainTestSupport.http;
import static org.microproxy.ChainTestSupport.open;
import static org.microproxy.ChainTestSupport.status;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.microproxy.ProxyFailure.TlsFailed.Reason;
import org.microproxy.tls.BrowserProfile;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * A server (or the chained proxy in front of it) that closes or resets the connection during the
 * proxy's TLS handshake with it, without a TLS alert, makes that handshake fail: a {@link
 * ProxyFailure.TlsFailed} whose reason says the connection closed, before or after the proxy's
 * ClientHello, a {@code tlsHandshakeFailed} event, and the next route if there is one. It is not
 * taken for a server that does not speak TLS (which would tunnel the client to it over a new
 * connection and record a successful tunnel).
 *
 * <p>The fakes act at exact points of the exchange: a chained proxy that answers the {@code
 * CONNECT} with {@code 200} and resets (or closes) the connection once the client has that answer,
 * before the client sends its ClientHello; and a chained proxy or a server that reads the proxy's
 * ClientHello and then resets (or closes). Each runs with the JDK's TLS and with a browser
 * profile's ({@link BrowserProfile}), as a fingerprint sidecar uses.
 */
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class MitmHandshakeClosedTest {

    static final CertificateAuthority proxyCa = CertificateAuthority.generate("Closed Handshake Proxy CA");
    static final CertificateAuthority originCa = CertificateAuthority.generate("Closed Handshake Origin CA");

    /** The TLS stack of the proxy's handshakes with servers. */
    enum Stack {
        JDK, BROWSER_PROFILE;

        SSLContext context() throws Exception {
            return this == JDK ? originCa.clientContext() : BrowserProfile.chrome156().sslContext(trusting(originCa));
        }
    }

    /** Where and how a fake ends the connection. */
    enum Fault {
        /** After the {@code CONNECT}'s {@code 200} (and the client's having it), before any ClientHello: a reset. */
        RESET_AFTER_200(true, false),
        /** After the {@code CONNECT}'s {@code 200}, before any ClientHello: a close. */
        CLOSE_AFTER_200(false, false),
        /** After reading the proxy's ClientHello: a reset. */
        RESET_AFTER_HELLO(true, true),
        /** After reading the proxy's ClientHello: a close. */
        CLOSE_AFTER_HELLO(false, true);

        final boolean reset;
        final boolean afterHello;

        Fault(boolean reset, boolean afterHello) {
            this.reset = reset;
            this.afterHello = afterHello;
        }
    }

    private final List<AutoCloseable> closeables = new ArrayList<>();
    private final RecordedFlows flows = new RecordedFlows();
    private final List<Throwable> handshakeFailures = new CopyOnWriteArrayList<>();
    private final AtomicInteger serverConnections = new AtomicInteger();
    /** The client has the {@code CONNECT}'s answer. */
    private final CountDownLatch clientConnected = new CountDownLatch(1);

    @AfterEach
    void tearDown() throws Exception {
        for (AutoCloseable c : closeables.reversed()) c.close();
    }

    static X509TrustManager trusting(CertificateAuthority ca) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setCertificateEntry("ca", ca.getCertificate());
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
        tmf.init(ks);
        return (X509TrustManager) tmf.getTrustManagers()[0];
    }

    private HttpProxyServerBootstrap proxy(Stack stack) throws Exception {
        return MicroProxy.bootstrap().withPort(0)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, stack.context()))
                .plusActivityTracker(flows)
                .plusActivityTracker(new ActivityTrackerAdapter() {
                    @Override
                    public void tlsHandshakeFailed(FlowContext flowContext, boolean clientSide, Throwable cause) {
                        if (!clientSide) handshakeFailures.add(cause);
                    }

                    @Override
                    public void serverConnected(FullFlowContext flowContext, java.net.InetSocketAddress server) {
                        serverConnections.incrementAndGet();
                    }
                });
    }

    private HttpProxyServer start(HttpProxyServerBootstrap bootstrap) {
        HttpProxyServer proxy = bootstrap.start();
        closeables.add(proxy::abort);
        return proxy;
    }

    /** Reads one TLS record (the ClientHello's first) from {@code in}. */
    private static void readRecord(InputStream in) throws IOException {
        DataInputStream data = new DataInputStream(in);
        byte[] header = new byte[5];
        data.readFully(header);
        assertEquals(0x16, header[0], "a TLS handshake record");
        data.readFully(new byte[((header[3] & 0xff) << 8) | (header[4] & 0xff)]);
    }

    private static void end(Socket s, boolean reset) throws IOException {
        if (reset) s.setSoLinger(true, 0);
        s.close();
    }

    /**
     * A chained proxy that answers the {@code CONNECT} with {@code 200}, then ends the connection as
     * {@code fault} says, counting the connections it accepted in {@code accepted}.
     */
    private TestSupport.RawServer chainedProxy(Fault fault, AtomicInteger accepted, CountDownLatch ended) {
        TestSupport.RawServer server = TestSupport.rawServer(s -> {
            accepted.incrementAndGet();
            TestSupport.readUntil(s.getInputStream(), "\r\n\r\n");
            TestSupport.write(s.getOutputStream(), "HTTP/1.1 200 Connection established\r\n\r\n");
            if (fault.afterHello) {
                readRecord(s.getInputStream());
            } else {
                // Not before the client has the CONNECT's answer, which the proxy sends once it has this one.
                clientConnected.await();
            }
            end(s, fault.reset);
            ended.countDown();
        });
        closeables.add(server);
        return server;
    }

    /** A server that reads the proxy's ClientHello and ends the connection as {@code fault} says. */
    private TestSupport.RawServer origin(Fault fault, AtomicInteger accepted) {
        TestSupport.RawServer server = TestSupport.rawServer(s -> {
            accepted.incrementAndGet();
            readRecord(s.getInputStream());
            end(s, fault.reset);
        });
        closeables.add(server);
        return server;
    }

    /**
     * CONNECTs to {@code target}, then (once {@code beforeHello} is open) runs the client's
     * handshake with the proxy and sends a GET in the session: returns that GET's status.
     */
    private int getThroughConnect(HttpProxyServer proxy, String target, CountDownLatch beforeHello) throws Exception {
        try (Socket s = open(proxy.getListenAddress())) {
            String established = connect(s, target);
            assertEquals(200, status(established), established);
            clientConnected.countDown();
            assertTrue(beforeHello.await(20, TimeUnit.SECONDS), "the fake ended the connection");
            String host = target.substring(0, target.lastIndexOf(':'));
            SSLSocket tls = (SSLSocket) proxyCa.clientContext().getSocketFactory().createSocket(s, host, 443, true);
            tls.startHandshake();
            TestSupport.write(tls.getOutputStream(), "GET / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n");
            return status(TestSupport.readUntil(tls.getInputStream(), "\r\n\r\n"));
        }
    }

    private static Reason expected(Fault fault) {
        return fault == Fault.RESET_AFTER_200 ? Reason.CLOSED_BEFORE_CLIENT_HELLO : Reason.CLOSED_DURING_HANDSHAKE;
    }

    /** The session's request was answered 502 for the handshake that the connection's end failed. */
    private ProxyFailure.TlsFailed assertTlsFailed(Reason reason) {
        FlowRecord tunnel = flows.await(FlowRecord.Kind.TUNNEL);
        // The CONNECT was answered before the server's handshake (deferred): its record says why that failed.
        assertEquals(200, tunnel.responseCode());
        assertTrue(tunnel.upstreamTransportFailureReason() != null
                && tunnel.upstreamTransportFailureReason().startsWith(reason.code() + ": "),
                "the tunnel's transport failure: " + tunnel.upstreamTransportFailureReason());
        FlowRecord request = flows.await("the session's request", r -> r.kind() != FlowRecord.Kind.TUNNEL);
        assertEquals(502, request.responseCode());
        assertEquals("proxy_failure:tls_failed", request.responseCodeDetails());
        assertTrue(request.responseFlags().contains(ResponseFlag.UPSTREAM_CONNECTION_FAILURE), request.responseFlags().toString());
        ProxyFailure.TlsFailed failure = assertInstanceOf(ProxyFailure.TlsFailed.class, request.failure().orElseThrow());
        assertEquals(reason, failure.reason());
        assertEquals(null, failure.alert());
        assertTrue(request.upstreamTransportFailureReason().startsWith(reason.code() + ": "),
                request.upstreamTransportFailureReason());
        assertTrue(handshakeFailures.contains(failure.cause()), "tlsHandshakeFailed got the handshake's exception");
        return failure;
    }

    @ParameterizedTest
    @EnumSource(Stack.class)
    void aChainedProxyThatResetsAfterItsConnect200(Stack stack) throws Exception {
        throughAChainedProxy(stack, Fault.RESET_AFTER_200);
    }

    @ParameterizedTest
    @EnumSource(Stack.class)
    void aChainedProxyThatClosesAfterItsConnect200(Stack stack) throws Exception {
        throughAChainedProxy(stack, Fault.CLOSE_AFTER_200);
    }

    @ParameterizedTest
    @EnumSource(Stack.class)
    void aChainedProxyThatResetsAfterTheClientHello(Stack stack) throws Exception {
        throughAChainedProxy(stack, Fault.RESET_AFTER_HELLO);
    }

    @ParameterizedTest
    @EnumSource(Stack.class)
    void aChainedProxyThatClosesAfterTheClientHello(Stack stack) throws Exception {
        throughAChainedProxy(stack, Fault.CLOSE_AFTER_HELLO);
    }

    private void throughAChainedProxy(Stack stack, Fault fault) throws Exception {
        AtomicInteger accepted = new AtomicInteger();
        CountDownLatch ended = new CountDownLatch(1);
        TestSupport.RawServer chained = chainedProxy(fault, accepted, ended);
        HttpProxyServer proxy = start(proxy(stack).withChainProxyManager(always(http(chained.address()))));
        int status = getThroughConnect(proxy, "origin.test:443", fault.afterHello ? new CountDownLatch(0) : ended);
        assertEquals(502, status);
        assertTlsFailed(expected(fault));
        // One attempt: no second connection, as when the server was taken for one that does not speak TLS.
        assertEquals(1, accepted.get());
        assertEquals(1, serverConnections.get());
        assertEquals(1, handshakeFailures.size());
    }

    @ParameterizedTest
    @EnumSource(Stack.class)
    void aServerThatResetsAfterTheClientHello(Stack stack) throws Exception {
        directly(stack, Fault.RESET_AFTER_HELLO);
    }

    @ParameterizedTest
    @EnumSource(Stack.class)
    void aServerThatClosesAfterTheClientHello(Stack stack) throws Exception {
        directly(stack, Fault.CLOSE_AFTER_HELLO);
    }

    private void directly(Stack stack, Fault fault) throws Exception {
        AtomicInteger accepted = new AtomicInteger();
        TestSupport.RawServer origin = origin(fault, accepted);
        HttpProxyServer proxy = start(proxy(stack));
        assertEquals(502, getThroughConnect(proxy, "localhost:" + origin.port(), new CountDownLatch(0)));
        assertTlsFailed(expected(fault));
        assertEquals(1, accepted.get());
        assertEquals(1, handshakeFailures.size());
    }

    @ParameterizedTest
    @EnumSource(Stack.class)
    void everyRouteResettingExhaustsTheRetries(Stack stack) throws Exception {
        AtomicInteger first = new AtomicInteger();
        AtomicInteger second = new AtomicInteger();
        TestSupport.RawServer a = chainedProxy(Fault.RESET_AFTER_HELLO, first, new CountDownLatch(1));
        TestSupport.RawServer b = chainedProxy(Fault.RESET_AFTER_HELLO, second, new CountDownLatch(1));
        HttpProxyServer proxy = start(proxy(stack).withChainProxyManager(always(http(a.address()), http(b.address()))));
        assertEquals(502, getThroughConnect(proxy, "origin.test:443", new CountDownLatch(0)));
        ProxyFailure.TlsFailed failure = assertTlsFailed(Reason.CLOSED_DURING_HANDSHAKE);
        FlowRecord request = flows.await("the session's request", r -> r.kind() != FlowRecord.Kind.TUNNEL);
        assertTrue(request.responseFlags().contains(ResponseFlag.UPSTREAM_RETRY_LIMIT_EXCEEDED), request.responseFlags().toString());
        // Each route once, each handshake reported; the last one's is the request's failure.
        assertEquals(1, first.get());
        assertEquals(1, second.get());
        assertEquals(2, handshakeFailures.size());
        assertEquals(failure.cause(), handshakeFailures.getLast());
    }

    @ParameterizedTest
    @EnumSource(Stack.class)
    void eagerlyTheConnectItselfIsAnswered502(Stack stack) throws Exception {
        AtomicInteger accepted = new AtomicInteger();
        TestSupport.RawServer chained = chainedProxy(Fault.RESET_AFTER_HELLO, accepted, new CountDownLatch(1));
        HttpProxyServer proxy = start(proxy(stack).withChainProxyManager(always(http(chained.address())))
                .onAllProtocols(p -> p.mitmServerHandshake(MitmServerHandshake.EAGER)));
        try (Socket s = open(proxy.getListenAddress())) {
            assertEquals(502, status(connect(s, "origin.test:443")));
        }
        FlowRecord tunnel = flows.await(FlowRecord.Kind.TUNNEL);
        assertEquals(502, tunnel.responseCode());
        ProxyFailure.TlsFailed failure = assertInstanceOf(ProxyFailure.TlsFailed.class, tunnel.failure().orElseThrow());
        assertEquals(Reason.CLOSED_DURING_HANDSHAKE, failure.reason());
        assertTrue(tunnel.responseFlags().contains(ResponseFlag.UPSTREAM_CONNECTION_FAILURE), tunnel.responseFlags().toString());
        assertEquals(1, accepted.get());
        assertEquals(1, handshakeFailures.size());
    }

    @Test
    void aServerThatAnswersInPlaintextIsStillTunnelled() throws Exception {
        // The positive sign of a server that does not speak TLS: bytes that are not a TLS record.
        TestSupport.RawServer plain = TestSupport.rawServer(s -> {
            s.getInputStream().read();
            TestSupport.write(s.getOutputStream(), "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
            s.shutdownOutput();
            s.getInputStream().readAllBytes();
        });
        closeables.add(plain);
        HttpProxyServer proxy = start(proxy(Stack.JDK).onAllProtocols(p -> p.mitmServerHandshake(MitmServerHandshake.EAGER)));
        try (Socket s = open(proxy.getListenAddress())) {
            assertEquals(200, status(connect(s, "localhost:" + plain.port())));
            s.getOutputStream().write("x".getBytes(StandardCharsets.US_ASCII));
            assertTrue(TestSupport.readUntil(s.getInputStream(), "\r\n\r\n").startsWith("HTTP/1.1 400"));
        }
        assertEquals(0, handshakeFailures.size());
    }
}
