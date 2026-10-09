package org.microproxy.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.microproxy.TestSupport.write;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.time.Duration;
import java.util.Properties;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.microproxy.ChainedProxy;
import org.microproxy.ChainedProxyAdapter;
import org.microproxy.HttpProxyServer;
import org.microproxy.MicroProxy;
import org.microproxy.TestSupport;
import org.microproxy.http.HttpMethod;
import org.microproxy.tls.SelfSignedSslContextSource;
import org.microproxy.tls.SslContexts;

/**
 * A peer that sends a byte now and then never trips the idle timeout, so without an overall
 * deadline it could hold a TLS handshake (and a connection) open forever.
 */
class TlsHandshakeTimeoutTest {

    private HttpProxyServer proxy;

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.abort();
    }

    /** Sends the start of a TLS record that never completes, one byte every 100 ms, until closed. */
    private static void trickle(OutputStream out) throws IOException, InterruptedException {
        byte[] start = {0x16, 0x03, 0x01, 0x40, 0x00};
        for (byte b : start) {
            out.write(b);
            out.flush();
            Thread.sleep(100);
        }
        for (int i = 0; i < 300; i++) {
            out.write(0);
            out.flush();
            Thread.sleep(100);
        }
    }

    @Test
    void clientsThatStallTheHandshakeAreDisconnected() throws Exception {
        proxy = MicroProxy.bootstrap().withPort(0).withSslContextSource(new SelfSignedSslContextSource())
                .withIdleConnectionTimeout(30).withTlsHandshakeTimeout(Duration.ofMillis(400)).start();
        try (Socket s = new Socket(proxy.getListenAddress().getAddress(), proxy.getListenAddress().getPort())) {
            s.setSoTimeout(10_000);
            long start = System.nanoTime();
            Thread writer = Thread.ofVirtual().start(() -> {
                try {
                    trickle(s.getOutputStream());
                } catch (IOException | InterruptedException expected) {
                    // the proxy closed the connection
                }
            });
            InputStream in = s.getInputStream();
            try {
                while (in.read() >= 0) {
                    // a TLS alert, if any
                }
            } catch (IOException closed) {
                // reset by the proxy
            }
            long elapsed = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
            assertTrue(elapsed < 5_000, "closed after " + elapsed + " ms");
            writer.interrupt();
        }
    }

    @Test
    void serversThatStallTheHandshakeGiveBadGateway() throws Exception {
        try (TestSupport.RawServer stalling = TestSupport.rawServer(socket -> trickle(socket.getOutputStream()))) {
            ChainedProxy tlsUpstream = new ChainedProxyAdapter() {
                @Override
                public InetSocketAddress getChainedProxyAddress() {
                    return new InetSocketAddress(TestSupport.LOOPBACK, stalling.port());
                }

                @Override
                public boolean requiresEncryption() {
                    return true;
                }

                @Override
                public SSLContext getSslContext() {
                    return SslContexts.trustAll();
                }
            };
            proxy = MicroProxy.bootstrap().withPort(0).withTlsHandshakeTimeout(Duration.ofMillis(400))
                    .withChainProxyManager((request, chain, client) -> chain.add(tlsUpstream)).start();
            try (Socket s = new Socket(proxy.getListenAddress().getAddress(), proxy.getListenAddress().getPort())) {
                s.setSoTimeout(10_000);
                long start = System.nanoTime();
                write(s.getOutputStream(), "GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\n\r\n");
                WireLevelTest.Reply reply = WireLevelTest.read(new ByteReader(s.getInputStream(), 1024), HttpMethod.GET);
                long elapsed = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
                assertEquals(502, reply.head().status().code());
                assertTrue(elapsed < 5_000, "answered after " + elapsed + " ms");
            }
        }
    }

    @Test
    void timeoutIsConfigurable() {
        assertEquals(Duration.ofSeconds(10), new DefaultHttpProxyServerBootstrap().tlsHandshakeTimeout);
        Properties p = new Properties();
        p.setProperty("tls_handshake_timeout", "2500");
        assertEquals(Duration.ofMillis(2500), DefaultHttpProxyServerBootstrap.fromProperties(p).tlsHandshakeTimeout);
        p.setProperty("tls_handshake_timeout", "0");
        assertEquals(Duration.ZERO, DefaultHttpProxyServerBootstrap.fromProperties(p).tlsHandshakeTimeout);
    }
}
