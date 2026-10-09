package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BooleanSupplier;
import javax.net.ssl.SSLSession;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;

/**
 * Activity trackers are isolated from each other and from the proxy: one that throws on every
 * callback breaks neither the request nor the trackers after it (LittleProxy's
 * ProxyToServerConnectionTest and ClientToProxyConnectionTest tracker cases).
 */
class ActivityTrackerTest {

    /** Throws from every callback. */
    static final class ThrowingTracker implements ActivityTracker {
        private static RuntimeException boom() {
            return new IllegalStateException("tracker failure (expected by the test)");
        }

        @Override
        public void clientConnected(FlowContext ctx) {
            throw boom();
        }

        @Override
        public void clientSSLHandshakeStarted(FlowContext ctx) {
            throw boom();
        }

        @Override
        public void clientSSLHandshakeSucceeded(FlowContext ctx, SSLSession session) {
            throw boom();
        }

        @Override
        public void clientDisconnected(FlowContext ctx, SSLSession session) {
            throw boom();
        }

        @Override
        public void bytesReceivedFromClient(FlowContext ctx, int n) {
            throw boom();
        }

        @Override
        public void requestReceivedFromClient(FlowContext ctx, HttpRequest request) {
            throw boom();
        }

        @Override
        public void bytesSentToServer(FullFlowContext ctx, int n) {
            throw boom();
        }

        @Override
        public void requestSentToServer(FullFlowContext ctx, HttpRequest request) {
            throw boom();
        }

        @Override
        public void bytesReceivedFromServer(FullFlowContext ctx, int n) {
            throw boom();
        }

        @Override
        public void responseReceivedFromServer(FullFlowContext ctx, HttpResponse response) {
            throw boom();
        }

        @Override
        public void bytesSentToClient(FlowContext ctx, int n) {
            throw boom();
        }

        @Override
        public void responseSentToClient(FlowContext ctx, HttpResponse response) {
            throw boom();
        }

        @Override
        public void serverConnected(FullFlowContext ctx, InetSocketAddress address) {
            throw boom();
        }

        @Override
        public void serverDisconnected(FullFlowContext ctx, InetSocketAddress address) {
            throw boom();
        }

        @Override
        public void connectionTimedOut(FlowContext ctx) {
            throw boom();
        }

        @Override
        public void connectionExceptionCaught(FlowContext ctx, Throwable cause) {
            throw boom();
        }
    }

    /** Records which callbacks ran and how many bytes were reported. */
    static final class RecordingTracker extends ActivityTrackerAdapter {
        final Set<String> events = ConcurrentHashMap.newKeySet();
        final List<String> disconnects = new CopyOnWriteArrayList<>();
        final AtomicLong bytes = new AtomicLong();

        @Override
        public void clientConnected(FlowContext ctx) {
            events.add("clientConnected");
        }

        @Override
        public void clientDisconnected(FlowContext ctx, SSLSession session) {
            disconnects.add(String.valueOf(ctx.getClientAddress()));
            events.add("clientDisconnected");
        }

        @Override
        public void bytesReceivedFromClient(FlowContext ctx, int n) {
            bytes.addAndGet(n);
        }

        @Override
        public void requestReceivedFromClient(FlowContext ctx, HttpRequest request) {
            events.add("requestReceivedFromClient");
        }

        @Override
        public void requestSentToServer(FullFlowContext ctx, HttpRequest request) {
            events.add("requestSentToServer");
        }

        @Override
        public void responseReceivedFromServer(FullFlowContext ctx, HttpResponse response) {
            events.add("responseReceivedFromServer");
        }

        @Override
        public void responseSentToClient(FlowContext ctx, HttpResponse response) {
            events.add("responseSentToClient");
        }

        @Override
        public void serverConnected(FullFlowContext ctx, InetSocketAddress address) {
            events.add("serverConnected");
        }

        @Override
        public void serverDisconnected(FullFlowContext ctx, InetSocketAddress address) {
            events.add("serverDisconnected");
        }

        @Override
        public void connectionTimedOut(FlowContext ctx) {
            events.add("connectionTimedOut");
        }
    }

    private HttpServer origin;
    private HttpProxyServer proxy;
    private final RecordingTracker recording = new RecordingTracker();

    /** Silences the warnings the throwing tracker causes (held strongly so the level sticks). */
    private final java.util.logging.Logger trackersLog = java.util.logging.Logger.getLogger("org.microproxy.impl.Trackers");
    private java.util.logging.Level previousLevel;

    @BeforeEach
    void setUp() {
        previousLevel = trackersLog.getLevel();
        trackersLog.setLevel(java.util.logging.Level.OFF);
        origin = TestSupport.origin(TestSupport.fixed(200, "tracked"));
    }

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.abort();
        origin.stop(0);
        trackersLog.setLevel(previousLevel);
    }

    private static void await(BooleanSupplier condition, String what) throws InterruptedException {
        long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() > deadline) throw new AssertionError("timed out waiting for " + what);
            Thread.sleep(10);
        }
    }

    @Test
    void throwingTrackerBreaksNeitherTheRequestNorLaterTrackers() throws Exception {
        proxy = MicroProxy.bootstrap().withPort(0)
                .plusActivityTracker(new ThrowingTracker())
                .plusActivityTracker(recording)
                .start();
        String response = TestSupport.rawExchange(proxy.getListenAddress(),
                "GET " + TestSupport.url(origin, "/") + " HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
        assertTrue(response.startsWith("HTTP/1.1 200"), response);
        assertTrue(response.endsWith("tracked"), response);

        await(() -> recording.events.containsAll(List.of("clientDisconnected", "serverDisconnected")), "disconnects");
        assertEquals(Set.of("clientConnected", "requestReceivedFromClient", "serverConnected", "requestSentToServer",
                "responseReceivedFromServer", "responseSentToClient", "clientDisconnected", "serverDisconnected"),
                recording.events);
        assertTrue(recording.bytes.get() > 0, "byte counts are reported too");
    }

    @Test
    void clientDisconnectIsReportedWithoutAnyRequest() throws Exception {
        proxy = MicroProxy.bootstrap().withPort(0).plusActivityTracker(new ThrowingTracker())
                .plusActivityTracker(recording).start();
        InetSocketAddress local;
        try (Socket s = new Socket(TestSupport.LOOPBACK, proxy.getListenAddress().getPort())) {
            local = (InetSocketAddress) s.getLocalSocketAddress();
            await(() -> recording.events.contains("clientConnected"), "clientConnected");
        }
        await(() -> recording.events.contains("clientDisconnected"), "clientDisconnected");
        assertFalse(recording.events.contains("requestReceivedFromClient"));
        assertEquals(1, recording.disconnects.size());
        assertTrue(recording.disconnects.get(0).endsWith(":" + local.getPort()),
                "the flow context names the client: " + recording.disconnects);
    }

    @Test
    void throwingTrackerDoesNotKeepATimedOutConnectionOpen() throws IOException, InterruptedException {
        proxy = MicroProxy.bootstrap().withPort(0).withIdleConnectionTimeout(Duration.ofMillis(200))
                .plusActivityTracker(new ThrowingTracker()).plusActivityTracker(recording).start();
        try (Socket s = new Socket(TestSupport.LOOPBACK, proxy.getListenAddress().getPort())) {
            s.setSoTimeout(5000);
            assertEquals(-1, s.getInputStream().read());
        }
        await(() -> recording.events.containsAll(List.of("connectionTimedOut", "clientDisconnected")), "timeout events");
    }
}
