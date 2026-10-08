package org.microproxy.impl;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
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
