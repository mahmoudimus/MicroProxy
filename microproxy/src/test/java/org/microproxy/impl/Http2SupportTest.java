package org.microproxy.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Properties;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.microproxy.Http2Options;
import org.microproxy.HttpProxyServer;
import org.microproxy.MicroProxy;

/** Enabling HTTP/2: the optional codec module, and the configuration keys. */
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
        assertTrue(b.http2Upstream);
        assertTrue(b.http2Cleartext);
        assertFalse(b.http2);
        assertTrue(b.copy().http2Upstream);
        assertTrue(b.copy().http2Cleartext);
        DefaultHttpProxyServerBootstrap none = DefaultHttpProxyServerBootstrap.fromProperties(new Properties());
        assertFalse(none.http2Upstream);
        assertFalse(none.http2Cleartext);
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
        assertTrue(b.http2);
        assertEquals(33, b.http2Options.maxConcurrentStreams());
        assertEquals(131_072, b.http2Options.initialWindowSize());
        assertEquals(4 << 20, b.http2Options.connectionWindowSize());
        assertEquals(Http2Options.DEFAULT.maxPings(), b.http2Options.maxPings());
        assertFalse(DefaultHttpProxyServerBootstrap.fromProperties(new Properties()).http2);
        // Copied with the rest of the configuration.
        assertTrue(b.copy().http2);
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
