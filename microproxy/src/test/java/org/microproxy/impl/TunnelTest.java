package org.microproxy.impl;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.Random;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.microproxy.ClientDetails;
import org.microproxy.FlowContext;
import org.microproxy.tcp.TcpInterceptor;

class TunnelTest {

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void failedHalfCloseReleasesTheOtherDirection(boolean failFlush) throws Exception {
        CountDownLatch closed = new CountDownLatch(1);
        InputStream blocked = new InputStream() {
            @Override
            public int read() throws IOException {
                try {
                    closed.await();
                    return -1;
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IOException(e);
                }
            }
        };
        ByteArrayOutputStream destination = new ByteArrayOutputStream() {
            @Override
            public void flush() throws IOException {
                if (failFlush) throw new IOException("flush failed");
            }
        };
        Thread relay = Thread.ofVirtual().start(() -> Tunnel.relay(
                new ByteArrayInputStream(new byte[0]), new ByteArrayOutputStream(), () -> {},
                blocked, destination, () -> { throw new IOException("half-close failed"); },
                closed::countDown, null, "failed-half-close", "", null, null, new BufferPool(16, 2)));
        try {
            assertTrue(closed.await(2, TimeUnit.SECONDS), "failure must close the blocked peer");
            relay.join(2000);
            assertFalse(relay.isAlive(), "relay must finish without an idle timeout");
        } finally {
            closed.countDown();
            relay.join(2000);
        }
    }

    /** Remembers which arrays the relay wrote from, to tell pooled buffers from copies. */
    private static final class Capture extends OutputStream {
        final List<byte[]> arrays = new CopyOnWriteArrayList<>();
        final ByteArrayOutputStream bytes = new ByteArrayOutputStream();

        @Override
        public void write(int b) {
            bytes.write(b);
        }

        @Override
        public void write(byte[] b, int off, int len) {
            arrays.add(b);
            bytes.write(b, off, len);
        }
    }

    private static byte[] payload() {
        byte[] data = new byte[1000];
        new Random(7).nextBytes(data);
        return data;
    }

    private static void relay(byte[] data, Capture toServer, TcpSession tcp, BufferPool pool) {
        Tunnel.relay(new ByteArrayInputStream(data), new ByteArrayOutputStream(), () -> {},
                new ByteArrayInputStream(new byte[0]), toServer, () -> {}, () -> {}, null, "fast-path", "",
                null, tcp, pool);
    }

    @Test
    void withoutTcpHooksBytesAreWrittenStraightFromPooledBuffers() {
        BufferPool pool = new BufferPool(4096, 4);
        byte[] pooled = pool.take();
        pool.give(pooled);
        byte[] data = payload();
        Capture toServer = new Capture();
        relay(data, toServer, null, pool);
        assertArrayEquals(data, toServer.bytes.toByteArray());
        assertFalse(toServer.arrays.isEmpty());
        // No copy: the relay writes from the buffer it read into, which goes back to the pool.
        for (byte[] written : toServer.arrays) assertSame(pooled, written);
        assertEquals(0, pool.outstanding());
    }

    @Test
    void tcpHooksGetCopiesAndGiveThePooledBufferBack() {
        BufferPool pool = new BufferPool(4096, 4);
        byte[] pooled = pool.take();
        pool.give(pooled);
        byte[] data = payload();
        List<byte[]> seen = new CopyOnWriteArrayList<>();
        TcpInterceptor interceptor = (message, ctx) -> {
            if (message.fromClient()) seen.add(message.data());
            return message.data();
        };
        FlowContext flow = new FlowContext(1, () -> new InetSocketAddress(0), () -> null, new ClientDetails());
        TcpSession tcp = new TcpSession(interceptor, flow, new HostAndPort("example.com", 25), false, null, null, "");
        Capture toServer = new Capture();
        relay(data, toServer, tcp, pool);
        assertArrayEquals(data, toServer.bytes.toByteArray());
        for (byte[] written : toServer.arrays) assertNotSame(pooled, written);
        assertEquals(data.length, seen.stream().mapToInt(b -> b.length).sum());
        assertEquals(0, pool.outstanding());
    }
}
