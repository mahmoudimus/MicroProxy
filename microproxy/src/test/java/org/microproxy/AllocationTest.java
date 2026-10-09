package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.management.ManagementFactory;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Guards the per-request allocation of the plain keep-alive path (about 4.7 KB per small GET, the
 * benchmark client included, when this was written). The bound is generous, so only a real
 * regression (such as a buffer or a copy per request) fails it, not noise.
 */
class AllocationTest {

    /** Bytes allocated per request, everything in the JVM included, above which the test fails. */
    private static final long MAX_BYTES_PER_REQUEST = 8 * 1024;
    private static final int CLIENTS = 4;

    private static final byte[] RESPONSE = ("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            + "Content-Length: 13\r\n\r\n{\"id\": 42}\n\n\n").getBytes(StandardCharsets.ISO_8859_1);

    private ServerSocket origin;
    private HttpProxyServer proxy;

    @BeforeEach
    void start() throws IOException {
        origin = new ServerSocket(0, 64, TestSupport.LOOPBACK);
        Thread.ofVirtual().start(() -> {
            while (!origin.isClosed()) {
                try {
                    Socket s = origin.accept();
                    Thread.ofVirtual().start(() -> serve(s));
                } catch (IOException e) {
                    return;
                }
            }
        });
        proxy = MicroProxy.bootstrap().withPort(0).start();
    }

    @AfterEach
    void stop() throws IOException {
        if (proxy != null) proxy.abort();
        origin.close();
    }

    @Test
    void smallKeepAliveRequestsAllocateLittle() throws Exception {
        com.sun.management.ThreadMXBean threads = (com.sun.management.ThreadMXBean) ManagementFactory.getThreadMXBean();
        assertTrue(threads.isThreadAllocatedMemorySupported() && threads.isThreadAllocatedMemoryEnabled(),
                "this JVM cannot count allocated bytes");
        byte[] request = ("GET http://127.0.0.1:" + origin.getLocalPort() + "/item?id=42 HTTP/1.1\r\n"
                + "Host: 127.0.0.1\r\nUser-Agent: allocation-test/1.0\r\nAccept: */*\r\n\r\n")
                .getBytes(StandardCharsets.ISO_8859_1);
        run(request, 5_000); // warm-up: class loading and JIT compilation
        long best = Long.MAX_VALUE;
        for (int round = 0; round < 3 && best > MAX_BYTES_PER_REQUEST; round++) {
            int perClient = 5_000;
            long before = threads.getTotalThreadAllocatedBytes();
            run(request, perClient);
            long perRequest = (threads.getTotalThreadAllocatedBytes() - before) / ((long) CLIENTS * perClient);
            best = Math.min(best, perRequest);
        }
        System.out.println("AllocationTest: " + best + " bytes allocated per small keep-alive request");
        assertTrue(best <= MAX_BYTES_PER_REQUEST, best + " bytes allocated per request, more than " + MAX_BYTES_PER_REQUEST);
    }

    /** {@link #CLIENTS} keep-alive connections, each sending {@code perClient} requests one after another. */
    private void run(byte[] request, int perClient) throws Exception {
        try (ExecutorService exec = Executors.newVirtualThreadPerTaskExecutor()) {
            List<Future<?>> clients = new ArrayList<>();
            for (int c = 0; c < CLIENTS; c++) {
                clients.add(exec.submit(() -> {
                    try (Socket s = new Socket(proxy.getListenAddress().getAddress(), proxy.getListenAddress().getPort())) {
                        s.setSoTimeout(20_000);
                        OutputStream out = s.getOutputStream();
                        InputStream in = s.getInputStream();
                        byte[] buf = new byte[4096];
                        for (int i = 0; i < perClient; i++) {
                            out.write(request);
                            readResponse(in, buf);
                        }
                    }
                    return null;
                }));
            }
            for (Future<?> f : clients) f.get();
        }
    }

    /** Reads one response with a 13-byte body, allocating nothing. */
    private static void readResponse(InputStream in, byte[] buf) throws IOException {
        int total = 0;
        int headEnd = -1;
        while (true) {
            int n = in.read(buf, total, buf.length - total);
            if (n < 0) throw new EOFException();
            total += n;
            if (headEnd < 0) {
                for (int i = 3; i < total; i++) {
                    if (buf[i] == '\n' && buf[i - 1] == '\r' && buf[i - 2] == '\n' && buf[i - 3] == '\r') {
                        headEnd = i + 1;
                        break;
                    }
                }
            }
            if (headEnd >= 0 && total >= headEnd + 13) {
                assertEquals(headEnd + 13, total, "one response at a time");
                return;
            }
        }
    }

    private static void serve(Socket s) {
        try (s) {
            InputStream in = s.getInputStream();
            OutputStream out = s.getOutputStream();
            byte[] buf = new byte[4096];
            int state = 0;
            int n;
            while ((n = in.read(buf)) > 0) {
                for (int i = 0; i < n; i++) {
                    byte c = buf[i];
                    // Counts CR LF CR LF: the end of a request head (the test sends no bodies).
                    state = c == (state % 2 == 0 ? '\r' : '\n') ? state + 1 : (c == '\r' ? 1 : 0);
                    if (state == 4) {
                        out.write(RESPONSE);
                        out.flush();
                        state = 0;
                    }
                }
            }
        } catch (IOException ignored) {
            // the test is over
        }
    }
}
