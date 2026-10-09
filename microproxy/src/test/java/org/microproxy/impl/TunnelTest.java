package org.microproxy.impl;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

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
                closed::countDown, null, "failed-half-close", "", null, 0, new BufferPool(16, 2)));
        try {
            assertTrue(closed.await(2, TimeUnit.SECONDS), "failure must close the blocked peer");
            relay.join(2000);
            assertFalse(relay.isAlive(), "relay must finish without an idle timeout");
        } finally {
            closed.countDown();
            relay.join(2000);
        }
    }
}
