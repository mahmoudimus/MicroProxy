package org.microproxy.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** The idle timeout of a wait for a peer's next bytes, kept without a timer per wait. */
class IdleWaitsTest {

    private ServerSocket listener;

    @BeforeEach
    void setUp() throws IOException {
        listener = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
    }

    @AfterEach
    void tearDown() throws IOException {
        listener.close();
    }

    /** A connected pair: [0] the side under test, [1] its peer. */
    private Socket[] pair() throws IOException {
        Socket client = new Socket(InetAddress.getLoopbackAddress(), listener.getLocalPort());
        Socket accepted = listener.accept();
        return new Socket[] {accepted, client};
    }

    /** Runs {@code body} on a virtual thread, as the proxy's connections do, and returns its result. */
    private static <T> T onVirtualThread(java.util.concurrent.Callable<T> body) throws Exception {
        CompletableFuture<T> result = new CompletableFuture<>();
        Thread.ofVirtual().start(() -> {
            try {
                result.complete(body.call());
            } catch (Throwable t) {
                result.completeExceptionally(t);
            }
        });
        try {
            return result.get(20, TimeUnit.SECONDS);
        } catch (java.util.concurrent.ExecutionException e) {
            if (e.getCause() instanceof Exception cause) throw cause;
            throw e;
        }
    }

    @Test
    void onlyPlainSocketsAreWatched() throws IOException {
        Socket[] s = pair();
        try {
            assertTrue(IdleWaits.supports(s[0]));
            assertFalse(IdleWaits.supports(null));
            assertFalse(IdleWaits.supports(new StreamSocket(null, null, null, null, null)), "a stream of a multiplexed connection");
            try (Socket tls = javax.net.ssl.SSLSocketFactory.getDefault().createSocket()) {
                assertFalse(IdleWaits.supports(tls), "a TLS socket keeps its SO_TIMEOUT");
            }
        } finally {
            s[0].close();
            s[1].close();
        }
    }

    @Test
    void bytesThatComeInTimeAreReadAndTheTimeoutIsKept() throws Exception {
        Socket[] s = pair();
        try (Socket under = s[0]; Socket peer = s[1]) {
            under.setSoTimeout(2000);
            Thread.ofVirtual().start(() -> {
                try {
                    Thread.sleep(200);
                    peer.getOutputStream().write('x');
                } catch (IOException | InterruptedException e) {
                    throw new RuntimeException(e);
                }
            });
            int b = onVirtualThread(() -> IdleWaits.readFirst(under, under.getInputStream()));
            assertEquals('x', b);
            assertEquals(2000, under.getSoTimeout(), "the socket's own timeout is put back");
            // The input was left alone: more bytes can still be read.
            peer.getOutputStream().write('y');
            assertEquals('y', under.getInputStream().read());
        }
    }

    @Test
    void aQuietPeerTimesOutAndTheSocketCanStillAnswer() throws Exception {
        Socket[] s = pair();
        try (Socket under = s[0]; Socket peer = s[1]) {
            under.setSoTimeout(300);
            long start = System.nanoTime();
            assertThrows(SocketTimeoutException.class,
                    () -> onVirtualThread(() -> IdleWaits.readFirst(under, under.getInputStream())));
            long millis = Duration.ofNanos(System.nanoTime() - start).toMillis();
            assertTrue(millis >= 250 && millis < 5000, "timed out after " + millis + " ms");
            under.getOutputStream().write("bye".getBytes(StandardCharsets.US_ASCII));
            peer.setSoTimeout(5000);
            InputStream in = peer.getInputStream();
            assertEquals('b', in.read(), "the timed-out side can still write");
        }
    }

    @Test
    void anEarlierDeadlineIsNotHeldUpByALaterOne() throws Exception {
        Socket[] slow = pair();
        Socket[] fast = pair();
        try (Socket a = slow[0]; Socket ap = slow[1]; Socket b = fast[0]; Socket bp = fast[1]) {
            a.setSoTimeout(10_000);
            CompletableFuture<Object> longWait = new CompletableFuture<>();
            Thread.ofVirtual().start(() -> {
                try {
                    longWait.complete(IdleWaits.readFirst(a, a.getInputStream()));
                } catch (Throwable t) {
                    longWait.completeExceptionally(t);
                }
            });
            Thread.sleep(100);
            b.setSoTimeout(200);
            long start = System.nanoTime();
            assertThrows(SocketTimeoutException.class, () -> onVirtualThread(() -> IdleWaits.readFirst(b, b.getInputStream())));
            long millis = Duration.ofNanos(System.nanoTime() - start).toMillis();
            assertTrue(millis < 5000, "the 200 ms wait took " + millis + " ms");
            assertFalse(longWait.isDone(), "the 10 s wait goes on");
            ap.getOutputStream().write('z');
            assertEquals((int) 'z', longWait.get(5, TimeUnit.SECONDS));
        }
    }

    @Test
    void noTimeoutWaitsForever() throws Exception {
        Socket[] s = pair();
        try (Socket under = s[0]; Socket peer = s[1]) {
            under.setSoTimeout(0);
            Thread.ofVirtual().start(() -> {
                try {
                    Thread.sleep(500);
                    peer.getOutputStream().write('q');
                } catch (IOException | InterruptedException e) {
                    throw new RuntimeException(e);
                }
            });
            assertEquals('q', (int) onVirtualThread(() -> IdleWaits.readFirst(under, under.getInputStream())));
        }
    }

    @Test
    void aClosingPeerEndsTheWaitWithEndOfStream() throws Exception {
        Socket[] s = pair();
        try (Socket under = s[0]) {
            under.setSoTimeout(5000);
            s[1].close();
            assertEquals(-1, (int) onVirtualThread(() -> IdleWaits.readFirst(under, under.getInputStream())));
        }
    }
}
