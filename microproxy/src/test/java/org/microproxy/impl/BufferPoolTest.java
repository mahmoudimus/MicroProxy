package org.microproxy.impl;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;
import org.microproxy.HttpProxyServer;
import org.microproxy.MicroProxy;

class BufferPoolTest {

    @Test
    void poolReusesUpToItsLimit() {
        BufferPool pool = new BufferPool(16, 1);
        byte[] a = pool.take();
        byte[] b = pool.take();
        assertEquals(2, pool.outstanding());
        pool.give(a);
        pool.give(b);
        assertEquals(1, pool.retained());
        assertEquals(0, pool.outstanding());
        assertTrue(pool.take() == a);
    }

    @Test
    void outputBufferIsHeldOnlyUntilFlush() throws Exception {
        BufferPool pool = new BufferPool(8, 4);
        ByteArrayOutputStream sink = new ByteArrayOutputStream();
        PooledOutputStream out = new PooledOutputStream(sink, pool);
        out.write("abc".getBytes(StandardCharsets.US_ASCII));
        assertEquals(1, pool.outstanding());
        out.write("defghijklmnop".getBytes(StandardCharsets.US_ASCII));
        out.write('q');
        out.flush();
        assertEquals(0, pool.outstanding());
        assertEquals("abcdefghijklmnopq", sink.toString(StandardCharsets.US_ASCII));
    }

    @Test
    void readerBorrowsOnDataAndReleasesWhenDrained() throws Exception {
        BufferPool pool = new BufferPool(4, 4);
        ByteReader in = new ByteReader(new ByteArrayInputStream("hello\nworld".getBytes(StandardCharsets.US_ASCII)), pool);
        in.awaitNext();
        assertEquals(1, pool.outstanding());
        assertEquals("hello", in.readLine(100, null));
        byte[] rest = new byte[5];
        in.readFully(rest, 0, 5);
        assertArrayEquals("world".getBytes(StandardCharsets.US_ASCII), rest);
        in.release();
        assertEquals(0, pool.outstanding());
        in.awaitNext();
        assertEquals(-1, in.read());
        assertEquals(0, pool.outstanding());
    }

    @Test
    void requestHeadReaderReleasesItsBufferWhileWaitingForMoreHeaderBytes() throws Exception {
        BufferPool pool = new BufferPool(128, 1);
        byte[] prefix = "GET / HTTP/1.1\r\nHost: example.test\r\nX-Slow: x"
                .getBytes(StandardCharsets.ISO_8859_1);
        CountDownLatch blocked = new CountDownLatch(1);
        CountDownLatch continueRead = new CountDownLatch(1);
        AtomicBoolean supplied = new AtomicBoolean();
        InputStream source = new InputStream() {
            @Override
            public int read() throws java.io.IOException {
                blocked.countDown();
                try {
                    continueRead.await();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new java.io.IOException(e);
                }
                return -1;
            }

            @Override
            public int read(byte[] b, int off, int len) throws java.io.IOException {
                if (supplied.compareAndSet(false, true)) {
                    System.arraycopy(prefix, 0, b, off, prefix.length);
                    return prefix.length;
                }
                return super.read(b, off, len);
            }
        };
        ByteReader reader = new ByteReader(source, pool).strictLineEndings();
        Thread parser = Thread.ofVirtual().start(() -> {
            try {
                HttpCodec.readRequest(reader, new HttpCodec.Limits(1024, 1024, 1024));
            } catch (java.io.IOException expectedAtEndOfTest) {
                // The test releases the blocked read with EOF after checking the pool.
            }
        });
        try {
            assertTrue(blocked.await(5, TimeUnit.SECONDS), "parser should wait for the rest of the header");
            assertEquals(0, pool.outstanding(), "a stalled request head must not pin its I/O buffer");
        } finally {
            continueRead.countDown();
            parser.join(5_000);
            reader.release();
        }
        assertFalse(parser.isAlive(), "parser should leave after the test supplies EOF");
        assertEquals(0, pool.outstanding());
    }

    @Test
    void idleConnectionsHoldNoBuffers() throws Exception {
        try (ServerSocket origin = new ServerSocket(0, 50, InetAddress.getLoopbackAddress())) {
            Thread.ofVirtual().start(() -> {
                try (Socket s = origin.accept()) {
                    InputStream in = s.getInputStream();
                    byte[] buf = new byte[4096];
                    StringBuilder sb = new StringBuilder();
                    while (sb.indexOf("\r\n\r\n") < 0) {
                        int n = in.read(buf);
                        if (n < 0) return;
                        sb.append(new String(buf, 0, n, StandardCharsets.ISO_8859_1));
                    }
                    s.getOutputStream().write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".getBytes(StandardCharsets.ISO_8859_1));
                    in.read(); // stay open, idle
                } catch (Exception ignored) {
                    // test origin
                }
            });
            HttpProxyServer proxy = MicroProxy.bootstrap().withPort(0).start();
            DefaultHttpProxyServer server = (DefaultHttpProxyServer) proxy;
            try (Socket client = new Socket(proxy.getListenAddress().getAddress(), proxy.getListenAddress().getPort())) {
                OutputStream out = client.getOutputStream();
                out.write(("GET http://127.0.0.1:" + origin.getLocalPort() + "/ HTTP/1.1\r\nHost: x\r\n\r\n")
                        .getBytes(StandardCharsets.ISO_8859_1));
                InputStream in = client.getInputStream();
                String response = "";
                byte[] buf = new byte[1024];
                while (!response.endsWith("ok")) {
                    int n = in.read(buf);
                    if (n < 0) break;
                    response += new String(buf, 0, n, StandardCharsets.ISO_8859_1);
                }
                assertTrue(response.startsWith("HTTP/1.1 200"), response);
                // Both the client and the server connection are now idle and kept alive.
                long deadline = System.nanoTime() + 5_000_000_000L;
                while ((server.ioBuffers.outstanding() != 0 || server.relayBuffers.outstanding() != 0)
                        && System.nanoTime() < deadline) {
                    Thread.sleep(10);
                }
                assertEquals(0, server.ioBuffers.outstanding());
                assertEquals(0, server.relayBuffers.outstanding());
            } finally {
                proxy.abort();
            }
        }
    }
}
