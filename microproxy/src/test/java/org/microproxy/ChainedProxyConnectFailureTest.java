package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
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
 * after reading the {@code CONNECT}. (A reset as soon as the fake accepts is not tested: it may
 * reach the proxy while its TCP connect is still finishing, a failed connection rather than a
 * failed {@code CONNECT}, so {@code OTHER}.)
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

    @Test
    void anUnreachableProxyIsNoChainedProxyAnswer() throws Exception {
        try (Socket refusing = TestSupport.refusingPort()) {
            ProxyFailure.ConnectFailed failure = connectThrough((InetSocketAddress) refusing.getLocalSocketAddress());
            assertEquals(Reason.OTHER, failure.reason());
            assertEquals(OptionalInt.empty(), failure.chainedProxyStatus());
        }
    }
}
