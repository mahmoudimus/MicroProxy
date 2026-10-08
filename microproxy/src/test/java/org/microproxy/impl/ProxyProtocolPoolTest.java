package org.microproxy.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.microproxy.TestSupport.write;

import java.io.InputStream;
import java.net.Socket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.microproxy.HttpProxyServer;
import org.microproxy.MicroProxy;
import org.microproxy.TestSupport;
import org.microproxy.http.HttpMethod;

/** A PROXY header names one client, so a connection that carries it must not serve another. */
class ProxyProtocolPoolTest {

    private HttpProxyServer proxy;

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.abort();
    }

    @Test
    void eachClientsRequestsCarryItsOwnAddress() throws Exception {
        // An origin that reads the PROXY header, then answers every request on the connection with
        // the source port the header named.
        try (TestSupport.RawServer origin = TestSupport.rawServer(socket -> {
                    InputStream in = socket.getInputStream();
                    String header = TestSupport.readUntil(in, "\r\n");
                    String sourcePort = header.strip().split(" ")[4];
                    while (true) {
                        TestSupport.readUntil(in, "\r\n\r\n");
                        write(socket.getOutputStream(), "HTTP/1.1 200 OK\r\nContent-Length: " + sourcePort.length()
                                + "\r\n\r\n" + sourcePort);
                    }
                })) {
            proxy = MicroProxy.bootstrap().withPort(0).withSendProxyProtocol(true)
                    .withSharedServerConnectionPool(true).start();
            for (int client = 0; client < 3; client++) {
                try (Socket s = new Socket(proxy.getListenAddress().getAddress(), proxy.getListenAddress().getPort())) {
                    s.setSoTimeout(10_000);
                    ByteReader in = new ByteReader(s.getInputStream(), 1024);
                    for (int request = 0; request < 2; request++) {
                        write(s.getOutputStream(), "GET http://127.0.0.1:" + origin.port() + "/ HTTP/1.1\r\nHost: x\r\n\r\n");
                        WireLevelTest.Reply reply = WireLevelTest.read(in, HttpMethod.GET);
                        assertEquals(String.valueOf(s.getLocalPort()), reply.body(), "client " + client + " request " + request);
                    }
                }
            }
        }
    }
}
