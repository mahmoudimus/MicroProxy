package org.microproxy.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.microproxy.TestSupport.write;

import java.net.Socket;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.microproxy.HttpProxyServer;
import org.microproxy.MicroProxy;
import org.microproxy.TestSupport;
import org.microproxy.http.HttpMethod;

/**
 * Requests must use CRLF line endings: a proxy that accepts a bare LF (or a stray CR) while the
 * server behind it does not, or the other way round, can be made to see a different request than
 * the server does.
 */
class LineEndingTest {

    private final AtomicInteger forwarded = new AtomicInteger();
    private TestSupport.RawServer origin;
    private HttpProxyServer proxy;

    @BeforeEach
    void setUp() {
        origin = TestSupport.rawServer(socket -> {
            TestSupport.readUntil(socket.getInputStream(), "\r\n\r\n");
            forwarded.incrementAndGet();
            write(socket.getOutputStream(), "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        });
        proxy = MicroProxy.bootstrap().withPort(0).start();
    }

    @AfterEach
    void tearDown() throws Exception {
        proxy.abort();
        origin.close();
    }

    private int status(String request) throws Exception {
        try (Socket s = new Socket(proxy.getListenAddress().getAddress(), proxy.getListenAddress().getPort())) {
            s.setSoTimeout(10_000);
            write(s.getOutputStream(), request);
            WireLevelTest.Reply reply = WireLevelTest.read(new ByteReader(s.getInputStream(), 1024), HttpMethod.POST);
            return reply == null ? -1 : reply.head().status().code();
        }
    }

    private String target() {
        return "http://127.0.0.1:" + origin.port() + "/";
    }

    @Test
    void crlfRequestsAreForwarded() throws Exception {
        assertEquals(200, status("POST " + target() + " HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
                + "2\r\nhi\r\n0\r\n\r\n"));
        assertEquals(1, forwarded.get());
    }

    @Test
    void bareLineFeedsAreRejected() throws Exception {
        String[] requests = {
            // request line
            "GET " + target() + " HTTP/1.1\nHost: x\r\n\r\n",
            // a header line
            "GET " + target() + " HTTP/1.1\r\nHost: x\nX-A: b\r\n\r\n",
            // the empty line ending the headers
            "GET " + target() + " HTTP/1.1\r\nHost: x\r\n\n",
            // a chunk size line
            "POST " + target() + " HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n2\nhi\r\n0\r\n\r\n",
            // after chunk data
            "POST " + target() + " HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\n0\r\n\r\n",
            // a stray CR inside a header line
            "GET " + target() + " HTTP/1.1\r\nHost: x\r\nX-A: b\rX-B: c\r\n\r\n",
        };
        StringBuilder got = new StringBuilder();
        for (String request : requests) got.append(status(request)).append(' ');
        assertEquals("400 400 400 400 400 400 ", got.toString());
        // The chunked cases fail after the head went out, with an unterminated body; the others never reach the server.
        assertEquals(true, forwarded.get() <= 2, "forwarded " + forwarded.get());
    }

    @Test
    void errorBodiesDoNotEchoTheRequest() throws Exception {
        try (Socket s = new Socket(proxy.getListenAddress().getAddress(), proxy.getListenAddress().getPort())) {
            s.setSoTimeout(10_000);
            write(s.getOutputStream(), "GET http://127.0.0.1:1/%3Cscript%3Ealert(1)%3C/script%3E<script> HTTP/1.1\r\n"
                    + "Host: x\r\n\r\n");
            WireLevelTest.Reply reply = WireLevelTest.read(new ByteReader(s.getInputStream(), 1024), HttpMethod.GET);
            assertEquals(502, reply.head().status().code());
            assertEquals("Bad Gateway", reply.body());
            assertEquals("text/plain; charset=utf-8", reply.head().headers().get("Content-Type"));
            assertEquals("nosniff", reply.head().headers().get("X-Content-Type-Options"));
        }
    }
}
