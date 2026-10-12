package org.microproxy.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.microproxy.Http2Options;
import org.microproxy.HttpProxyServer;
import org.microproxy.MicroProxy;

/** Enabling HTTP/2: on by default, the optional codec module, and the configuration keys. */
class Http2SupportTest {

    @AfterEach
    void restore() {
        Http2Support.presentForTesting = null;
    }

    @Test
    void theCodecIsOnTheTestClassPath() {
        assertTrue(Http2Support.available());
    }

    @Test
    void enablingHttp2WithoutTheCodecFailsAtStartup() {
        Http2Support.presentForTesting = false;
        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> MicroProxy.bootstrap().withPort(0).withHttp2(true).start());
        assertTrue(e.getMessage().contains("http2-codec"), e.getMessage());
        assertTrue(e.getMessage().contains("class path"), e.getMessage());
    }

    @Test
    void upstreamAndCleartextHttp2NeedTheCodecToo() {
        Http2Support.presentForTesting = false;
        IllegalStateException upstream = assertThrows(IllegalStateException.class,
                () -> MicroProxy.bootstrap().withPort(0).withHttp2Upstream(true).start());
        assertTrue(upstream.getMessage().contains("http2-codec"), upstream.getMessage());
        IllegalStateException cleartext = assertThrows(IllegalStateException.class,
                () -> MicroProxy.bootstrap().withPort(0).withHttp2Cleartext(true).start());
        assertTrue(cleartext.getMessage().contains("withHttp2Cleartext"), cleartext.getMessage());
    }

    @Test
    void propertiesEnableUpstreamAndCleartextHttp2() {
        Properties p = new Properties();
        p.setProperty("http2_upstream", "true");
        p.setProperty("http2_cleartext", "true");
        DefaultHttpProxyServerBootstrap b = DefaultHttpProxyServerBootstrap.fromProperties(p);
        assertEquals(Boolean.TRUE, b.http2Upstream);
        assertTrue(b.http2Cleartext);
        assertNull(b.http2, "left at the default");
        assertEquals(Boolean.TRUE, b.copy().http2Upstream);
        assertTrue(b.copy().http2Cleartext);
        DefaultHttpProxyServerBootstrap none = DefaultHttpProxyServerBootstrap.fromProperties(new Properties());
        assertNull(none.http2Upstream);
        assertTrue(none.offersHttp2Upstream(), "on by default");
        assertFalse(none.http2Cleartext, "h2c stays opt-in");
    }

    @Test
    void http2IsOnByDefaultAndTurnedOffExplicitly() {
        DefaultHttpProxyServerBootstrap defaults = (DefaultHttpProxyServerBootstrap) MicroProxy.bootstrap();
        assertNull(defaults.http2);
        assertNull(defaults.http2Upstream);
        assertTrue(defaults.offersHttp2());
        assertTrue(defaults.offersHttp2Upstream());
        assertFalse(defaults.http2Cleartext);
        DefaultHttpProxyServer server = (DefaultHttpProxyServer) defaults.withPort(0).start();
        try {
            assertTrue(server.http2);
            assertTrue(server.http2Upstream);
            assertFalse(server.http2Cleartext);
            assertNotNull(server.http2Origins, "HTTP/2 to servers needs its connections");
        } finally {
            server.abort();
        }
        DefaultHttpProxyServer off = (DefaultHttpProxyServer) MicroProxy.bootstrap().withPort(0).withHttp2(false)
                .withHttp2Upstream(false).start();
        try {
            assertFalse(off.http2);
            assertFalse(off.http2Upstream);
            assertNull(off.http2Origins);
        } finally {
            off.abort();
        }
        // Each one on its own, and kept by copies (each start copies the bootstrap).
        DefaultHttpProxyServerBootstrap clientsOnly = (DefaultHttpProxyServerBootstrap) MicroProxy.bootstrap()
                .withHttp2Upstream(false);
        assertTrue(clientsOnly.copy().offersHttp2());
        assertFalse(clientsOnly.copy().offersHttp2Upstream());
    }

    @Test
    void propertiesTurnHttp2Off() {
        Properties p = new Properties();
        p.setProperty("http2", "false");
        p.setProperty("http2_upstream", "false");
        DefaultHttpProxyServerBootstrap b = DefaultHttpProxyServerBootstrap.fromProperties(p);
        assertFalse(b.offersHttp2());
        assertFalse(b.offersHttp2Upstream());
        p.setProperty("http2", "true");
        p.remove("http2_upstream");
        b = DefaultHttpProxyServerBootstrap.fromProperties(p);
        assertEquals(Boolean.TRUE, b.http2, "set explicitly, so it fails without the codec");
        assertNull(b.http2Upstream);
    }

    @Test
    void anH2cOnlyListenerFromPropertiesAndWithoutTheCodec() {
        Properties p = new Properties();
        p.setProperty("http2_cleartext_only", "true");
        DefaultHttpProxyServerBootstrap b = DefaultHttpProxyServerBootstrap.fromProperties(p);
        assertTrue(b.http2CleartextOnly);
        assertTrue(b.copy().http2CleartextOnly);
        assertFalse(DefaultHttpProxyServerBootstrap.fromProperties(new Properties()).http2CleartextOnly);
        Http2Support.presentForTesting = false;
        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> MicroProxy.bootstrap().withPort(0).withHttp2CleartextOnly(true).start());
        assertTrue(e.getMessage().contains("http2-codec"), e.getMessage());
    }

    /**
     * Without the codec, the defaults fall back to HTTP/1.1 and say so at INFO once, then at
     * DEBUG; a server that turns both off says nothing. (Http2CodecAbsentTest serves requests so.)
     */
    @Test
    void theDefaultsFallBackToHttp1WithoutTheCodec() {
        Http2Support.presentForTesting = false;
        Http2Support.FALLBACK_LOGGED.set(false);
        TlsDiagnosticsTest.Captured log = new TlsDiagnosticsTest.Captured(Http2Support.class.getName());
        try {
            for (int i = 0; i < 2; i++) {
                DefaultHttpProxyServer server = (DefaultHttpProxyServer) MicroProxy.bootstrap().withPort(0).start();
                try {
                    assertFalse(server.http2);
                    assertFalse(server.http2Upstream);
                    assertNull(server.http2Origins);
                } finally {
                    server.abort();
                }
            }
            List<LogRecord> fallback = log.records.stream()
                    .filter(r -> r.getMessage().contains("on by default") && r.getMessage().contains("http2-codec"))
                    .toList();
            assertEquals(List.of(Level.INFO, Level.FINE), fallback.stream().map(LogRecord::getLevel).toList());
            log.records.clear();
            MicroProxy.bootstrap().withPort(0).withHttp2(false).withHttp2Upstream(false).start().abort();
            assertEquals(List.of(), log.records, "turned off, there is nothing to fall back from");
            // One left at its default is enough to fall back (and say so).
            DefaultHttpProxyServer one = (DefaultHttpProxyServer) MicroProxy.bootstrap().withPort(0).withHttp2(false).start();
            one.abort();
            assertFalse(one.http2Upstream);
            assertEquals(1, log.records.size());
        } finally {
            log.close();
        }
    }

    @Test
    void thePrefaceIsRecognizedWithoutConsumingAnything() throws Exception {
        byte[] preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        // Delivered a byte at a time, as a slow client would.
        java.io.InputStream oneByOne = new java.io.InputStream() {
            private int pos;

            @Override
            public int read() {
                return pos < preface.length ? preface[pos++] & 0xff : -1;
            }

            @Override
            public int read(byte[] b, int off, int len) {
                if (pos >= preface.length) return -1;
                b[off] = preface[pos++];
                return 1;
            }
        };
        ByteReader reader = new ByteReader(oneByOne, 64);
        assertTrue(reader.startsWith(preface));
        assertEquals(preface.length, reader.buffered());
        assertEquals('P', reader.read());
        // An HTTP/1 request is told apart at its second byte, and nothing is lost.
        ByteReader post = new ByteReader(new java.io.ByteArrayInputStream("POST / HTTP/1.1\r\n".getBytes(
                java.nio.charset.StandardCharsets.US_ASCII)), 64);
        assertFalse(post.startsWith(preface));
        assertEquals("POST / HTTP/1.1", post.readLine(100, org.microproxy.http.HttpResponseStatus.BAD_REQUEST));
        assertFalse(new ByteReader(java.io.InputStream.nullInputStream(), 64).startsWith(preface));
    }

    @Test
    void withoutHttp2TheCodecIsNotNeeded() {
        Http2Support.presentForTesting = false;
        HttpProxyServer proxy = MicroProxy.bootstrap().withPort(0).withHttp2(false).start();
        proxy.abort();
    }

    @Test
    void propertiesEnableAndConfigureHttp2() {
        Properties p = new Properties();
        p.setProperty("http2", "true");
        p.setProperty("http2_max_concurrent_streams", "33");
        p.setProperty("http2_initial_window_size", "131072");
        p.setProperty("http2_connection_window_size", "4194304");
        DefaultHttpProxyServerBootstrap b = DefaultHttpProxyServerBootstrap.fromProperties(p);
        assertEquals(Boolean.TRUE, b.http2);
        assertEquals(33, b.http2Options.maxConcurrentStreams());
        assertEquals(131_072, b.http2Options.initialWindowSize());
        assertEquals(4 << 20, b.http2Options.connectionWindowSize());
        assertEquals(Http2Options.DEFAULT.maxPings(), b.http2Options.maxPings());
        assertFalse(b.http2Options.coalesceConnections());
        p.setProperty("http2_coalesce", "true");
        assertTrue(DefaultHttpProxyServerBootstrap.fromProperties(p).http2Options.coalesceConnections());
        assertEquals(33, DefaultHttpProxyServerBootstrap.fromProperties(p).http2Options.maxConcurrentStreams());
        p.remove("http2_coalesce");
        assertNull(DefaultHttpProxyServerBootstrap.fromProperties(new Properties()).http2);
        // Copied with the rest of the configuration.
        assertEquals(Boolean.TRUE, b.copy().http2);
        assertEquals(33, b.copy().http2Options.maxConcurrentStreams());
    }

    @Test
    void optionsAreValidated() {
        assertThrows(IllegalArgumentException.class, () -> Http2Options.builder().maxConcurrentStreams(0));
        assertThrows(IllegalArgumentException.class, () -> Http2Options.builder().initialWindowSize(1000));
        assertThrows(IllegalArgumentException.class, () -> Http2Options.builder().rateWindow(java.time.Duration.ZERO));
        Http2Options o = Http2Options.builder().maxPings(5).build();
        assertEquals(5, o.toBuilder().build().maxPings());
        assertTrue(o.toString().contains("maxPings=5"));
    }
}
