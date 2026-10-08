package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class ProxyProtocolTest {

    private HttpProxyServer proxy;

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.abort();
    }

    @Test
    void acceptedHeaderSetsClientAddressAndIsForwarded() throws Exception {
        AtomicReference<InetSocketAddress> clientAddress = new AtomicReference<>();
        proxy = MicroProxy.bootstrap().withPort(0).withAcceptProxyProtocol(true).withSendProxyProtocol(true)
                .plusActivityTracker(new ActivityTrackerAdapter() {
                    @Override
                    public void clientConnected(FlowContext ctx) {
                        clientAddress.set(ctx.getClientAddress());
                    }
                }).start();
        CompletableFuture<String> received = new CompletableFuture<>();
        try (TestSupport.RawServer origin = TestSupport.rawServer(s -> {
            String head = TestSupport.readUntil(s.getInputStream(), "\r\n\r\n");
            received.complete(head);
            TestSupport.write(s.getOutputStream(), "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        })) {
            String response = TestSupport.rawExchange(proxy.getListenAddress(),
                    "PROXY TCP4 203.0.113.7 198.51.100.1 51234 443\r\n"
                            + "GET http://127.0.0.1:" + origin.port() + "/ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
            assertTrue(response.startsWith("HTTP/1.1 200"), response);
            String head = received.get(5, TimeUnit.SECONDS);
            assertTrue(head.startsWith("PROXY TCP4 203.0.113.7 198.51.100.1 51234 443\r\nGET / HTTP/1.1"), head);
        }
        assertEquals("203.0.113.7", clientAddress.get().getAddress().getHostAddress());
        assertEquals(51234, clientAddress.get().getPort());
    }

    @Test
    void binaryV2HeaderIsAccepted() throws Exception {
        AtomicReference<InetSocketAddress> clientAddress = new AtomicReference<>();
        proxy = MicroProxy.bootstrap().withPort(0).withAcceptProxyProtocol(true)
                .plusActivityTracker(new ActivityTrackerAdapter() {
                    @Override
                    public void clientConnected(FlowContext ctx) {
                        clientAddress.set(ctx.getClientAddress());
                    }
                }).start();
        try (Socket s = new Socket(proxy.getListenAddress().getAddress(), proxy.getListenAddress().getPort())) {
            OutputStream out = s.getOutputStream();
            out.write(new byte[] {0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
                0x21, 0x11, 0x00, 0x0C, (byte) 192, 0, 2, 9, 10, 0, 0, 1, 0x1F, (byte) 0x90, 0x01, (byte) 0xBB});
            out.write("GET /x HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
            out.flush();
            String response = new String(s.getInputStream().readAllBytes(), StandardCharsets.ISO_8859_1);
            assertTrue(response.startsWith("HTTP/1.1 400"), response);
        }
        assertEquals("192.0.2.9", clientAddress.get().getAddress().getHostAddress());
        assertEquals(8080, clientAddress.get().getPort());
    }

    @Test
    void missingHeaderIsRejected() throws Exception {
        proxy = MicroProxy.bootstrap().withPort(0).withAcceptProxyProtocol(true).start();
        String response = TestSupport.rawExchange(proxy.getListenAddress(),
                "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n");
        assertEquals("", response);
    }
}
