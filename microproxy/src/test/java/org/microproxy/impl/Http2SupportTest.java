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
