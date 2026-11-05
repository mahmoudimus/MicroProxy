package org.microproxy.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.mahmoudimus.quic.QuicStream;
import io.github.mahmoudimus.quic.QuicStreamException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.time.Duration;
import java.util.HashMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.BooleanSupplier;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.Http3Options;
import sun.misc.Unsafe;

/** The connection's removal of a received-reset flow must also release its global place. */
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class Http3UdpFlowReleaseTest {

    @Test
    void aRequestThatAlreadyFoundTheFlowWaitsForItsPlaceToBeReleased() throws Exception {
        try (Fixture f = new Fixture()) {
            // Let releaseEndedFlows snapshot the old stream, then stop it at QUIC's lock.
            f.quicLock.lock();
            try {
                f.requester.start();
                await(() -> f.quicLock.hasQueuedThread(f.requester));
                f.remover.start();
                f.flows.awaitRemoval();
                assertTrue(f.connection.stateLock.isLocked());
                assertFalse(f.flows.containsKey(8L));
                assertEquals(3, f.bound.held(), "map removal has not released the global place yet");
            } finally {
                f.quicLock.unlock();
            }

            // The broken fast path returns null; the correct path waits on stateLock. Resume
            // the old reader in either case, so a fixed implementation can finish its take.
            await(() -> f.replacement.isDone() || f.connection.stateLock.hasQueuedThread(f.requester));
            f.flows.resume.countDown();
            f.removal.get(10, TimeUnit.SECONDS);
            assertNotNull(f.replacement.get(10, TimeUnit.SECONDS),
                    "a received reset must release its global place before replacement admission");
            assertEquals(3, f.bound.held(), "the replacement holds the released place");
        }
    }

    @Test
    void aRequestThatScansAfterRemovalWaitsForItsPlaceToBeReleased() throws Exception {
        try (Fixture f = new Fixture()) {
            f.remover.start();
            f.flows.awaitRemoval();
            f.requester.start();
            // Enumeration must wait for the locked remove-and-release even though the map is empty.
            await(() -> f.connection.stateLock.hasQueuedThread(f.requester));
            assertFalse(f.replacement.isDone());
            assertEquals(3, f.bound.held());
            f.flows.resume.countDown();
            f.removal.get(10, TimeUnit.SECONDS);
            assertNotNull(f.replacement.get(10, TimeUnit.SECONDS));
            assertEquals(3, f.bound.held());
        }
    }

    /** Polls only the test's scheduling handshake, never the admission result or product timeout. */
    private static void await(BooleanSupplier reached) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (!reached.getAsBoolean() && System.nanoTime() < deadline) Thread.sleep(1);
        assertTrue(reached.getAsBoolean(), "worker did not reach the scheduling barrier");
    }

    /** Actual CHM removal, paused before udpFlowEnded can release the place under stateLock. */
    private static final class PausingFlows extends ConcurrentHashMap<Long, UdpFlow> {
        final CountDownLatch removed = new CountDownLatch(1);
        final CountDownLatch resume = new CountDownLatch(1);

        @Override
        public UdpFlow remove(Object key) {
            UdpFlow flow = super.remove(key);
            if (flow != null) {
                removed.countDown();
                try {
                    assertTrue(resume.await(10, TimeUnit.SECONDS), "removal was not resumed");
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new AssertionError("removal interrupted", e);
                }
            }
            return flow;
        }

        void awaitRemoval() throws InterruptedException {
            assertTrue(removed.await(10, TimeUnit.SECONDS), "flow was not removed");
        }
    }

    /**
     * Focused fixtures avoid starting unrelated listeners and flow relay threads. Reflection only
     * initializes the fields used here; admission, scanning, peerDone, endSeen and bound operations
     * all execute their production implementations. The sole scheduling seam is PausingFlows.
     */
    private static final class Fixture implements AutoCloseable {
        final UdpFlowBound bound = new UdpFlowBound();
        final ReentrantLock quicLock = new ReentrantLock();
        final PausingFlows flows = new PausingFlows();
        final Http3Connection connection;
        final FutureTask<UdpFlowBound.Place> replacement;
        final FutureTask<Object> removal;
        final Thread requester;
        final Thread remover;

        Fixture() throws Exception {
            assertNotNull(bound.take(3, 0));
            assertNotNull(bound.take(3, 0));
            UdpFlowBound.Place ending = bound.take(3, 0);
            assertNotNull(ending);
            UdpFlow flow = uninitialized(UdpFlow.class);
            set(flow, "place", ending);

            Object quicConnection = uninitialized(Class.forName("io.github.mahmoudimus.quic.connection.Connection"));
            Class<?> state = field(quicConnection.getClass(), "state").getType();
            @SuppressWarnings({"rawtypes", "unchecked"})
            Object established = Enum.valueOf((Class) state, "ESTABLISHED");
            set(quicConnection, "state", established);
            Object driver = uninitialized(Class.forName("io.github.mahmoudimus.quic.ConnectionDriver"));
            set(driver, "lock", quicLock);
            set(driver, "conn", quicConnection);
            Object input = uninitialized(Class.forName("io.github.mahmoudimus.quic.QuicStream$Input"));
            set(input, "reset", new QuicStreamException(QuicStreamException.Kind.RESET, 0x10c));
            QuicStream stream = uninitialized(QuicStream.class);
            set(stream, "driver", driver);
            set(stream, "input", input);
            assertTrue(stream.peerDone(), "QUIC has already observed the reset on an open connection");

            Http3StreamReader reader = uninitialized(Http3StreamReader.class);
            set(reader, "stream", stream);
            connection = uninitialized(Http3Connection.class);
            set(connection, "stateLock", new ReentrantLock());
            flows.put(8L, flow);
            set(connection, "udpFlows", flows);
            Http3StreamChannel channel = uninitialized(Http3StreamChannel.class);
            set(channel, "connection", connection);
            set(channel, "id", 8L);
            set(channel, "reader", reader);
            HashMap<Long, Http3StreamChannel> streams = new HashMap<>();
            streams.put(8L, channel);
            set(connection, "streams", streams);

            DefaultHttpProxyServer server = uninitialized(DefaultHttpProxyServer.class);
            set(server, "udpFlows", bound);
            set(server, "http3Options", Http3Options.builder().connectUdpMaxFlows(3, 2)
                    .connectUdpReleaseWait(Duration.ZERO).build());
            ClientConnection client = uninitialized(ClientConnection.class);
            set(client, "server", server);
            Method take = ClientConnection.class.getDeclaredMethod("takeUdpPlace", UdpFlow.Client.class);
            take.setAccessible(true);
            Method end = Http3Connection.class.getDeclaredMethod("udpFlowEnded", long.class);
            end.setAccessible(true);
            replacement = new FutureTask<>(() -> (UdpFlowBound.Place) take.invoke(client, channel));
            removal = new FutureTask<>(() -> end.invoke(connection, 8L));
            requester = Thread.ofVirtual().name("replacement-request").unstarted(replacement);
            remover = Thread.ofVirtual().name("old-reset-reader").unstarted(removal);
        }

        @Override
        public void close() {
            flows.resume.countDown();
            // Also release workers when an assertion or a scheduling guard fails. Neither task
            // owns external resources; both must terminate before another test can start.
            requester.interrupt();
            remover.interrupt();
            boolean interrupted = Thread.interrupted();
            boolean leaked = false;
            try {
                for (Thread worker : new Thread[] {requester, remover}) {
                    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
                    while (worker.isAlive() && System.nanoTime() < deadline) {
                        try {
                            worker.join(100);
                        } catch (InterruptedException e) {
                            interrupted = true;
                        }
                    }
                    leaked |= worker.isAlive();
                }
                assertFalse(leaked, "a test worker failed to terminate");
            } finally {
                if (interrupted) Thread.currentThread().interrupt();
            }
        }
    }

    private static <T> T uninitialized(Class<T> type) throws ReflectiveOperationException {
        Field singleton = Unsafe.class.getDeclaredField("theUnsafe");
        singleton.setAccessible(true);
        return type.cast(((Unsafe) singleton.get(null)).allocateInstance(type));
    }

    private static Field field(Class<?> type, String name) throws NoSuchFieldException {
        for (Class<?> c = type; c != null; c = c.getSuperclass()) {
            try {
                Field field = c.getDeclaredField(name);
                field.setAccessible(true);
                return field;
            } catch (NoSuchFieldException ignored) {
                // Search the inherited endpoint state too.
            }
        }
        throw new NoSuchFieldException(name);
    }

    private static void set(Object object, String name, Object value) throws ReflectiveOperationException {
        field(object.getClass(), name).set(object, value);
    }
}
