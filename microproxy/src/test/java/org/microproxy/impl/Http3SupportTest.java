package org.microproxy.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Properties;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.microproxy.Http3Options;
import org.microproxy.MicroProxy;
import org.microproxy.SslContextSource;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/** Enabling HTTP/3: the optional modules, where it can be served, its certificate, and the configuration keys. */
class Http3SupportTest {

    @AfterEach
    void restore() {
        Http3Support.presentForTesting = null;
    }

    @Test
    void theModulesAreOnTheTestClassPath() {
        assertTrue(Http3Support.available());
    }

    @Test
    void enablingHttp3WithoutTheModulesFailsAtStartup() {
        Http3Support.presentForTesting = false;
        IllegalStateException served = assertThrows(IllegalStateException.class, () -> MicroProxy.bootstrap().withPort(0)
                .withReverseProxy("http://127.0.0.1:1").withHttp3(true).start());
        assertTrue(served.getMessage().contains("quic") && served.getMessage().contains("http3-codec"), served.getMessage());
        IllegalStateException upstream = assertThrows(IllegalStateException.class,
                () -> MicroProxy.bootstrap().withPort(0).withHttp3Upstream(true).start());
        assertTrue(upstream.getMessage().contains("class path"), upstream.getMessage());
    }

    @Test
    void http3IsServedByAReverseProxyOrNextToAForwardProxysTlsListener() {
        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> MicroProxy.bootstrap().withPort(0).withHttp3(true).start());
        assertTrue(e.getMessage().contains("TLS listener"), e.getMessage());
        IllegalStateException transparent = assertThrows(IllegalStateException.class, () -> MicroProxy.bootstrap()
                .withPort(0).withTransparent(true).withSslContextSource(new org.microproxy.tls.SelfSignedSslContextSource())
                .withHttp3(true).start());
        assertTrue(transparent.getMessage().contains("transparent"), transparent.getMessage());
        IllegalStateException tcp = assertThrows(IllegalStateException.class,
                () -> MicroProxy.bootstrap().withPort(0).withReverseProxy("tcp://127.0.0.1:1").withHttp3(true).start());
        assertTrue(tcp.getMessage().contains("tcp://"), tcp.getMessage());
    }

    @Test
    void http3NeedsACertificate() {
        IllegalStateException none = assertThrows(IllegalStateException.class, () -> MicroProxy.bootstrap().withPort(0)
                .withReverseProxy("http://127.0.0.1:1").withHttp3(true).start());
        assertTrue(none.getMessage().contains("needs a certificate"), none.getMessage());
        SslContextSource opaque = org.microproxy.tls.SslContexts::systemDefault;
        IllegalStateException noKey = assertThrows(IllegalStateException.class, () -> MicroProxy.bootstrap().withPort(0)
                .withReverseProxy("http://127.0.0.1:1").withSslContextSource(opaque).withHttp3(true).start());
        assertTrue(noKey.getMessage().contains("getKeyMaterial"), noKey.getMessage());
    }

    @Test
    void aCertificateAuthorityIssuesTheListenersCertificate() {
        CertificateAuthorityMitmManager mitm = new CertificateAuthorityMitmManager(CertificateAuthority.generate("H3 CA"));
        var key = mitm.keyMaterialFor("example.com");
        assertEquals(2, key.chain().size());
        assertEquals(mitm.getCertificateAuthority().getCertificate(), key.chain().get(1));
        assertTrue(key == mitm.keyMaterialFor("example.com"), "cached per host");
        org.microproxy.HttpProxyServer proxy = MicroProxy.bootstrap().withPort(0)
                .withReverseProxy("http://127.0.0.1:1").withManInTheMiddle(mitm).withHttp3(true).start();
        proxy.abort();
    }

    @Test
    void propertiesEnableHttp3() {
        Properties p = new Properties();
        p.setProperty("http3", "true");
        p.setProperty("http3_upstream", "true");
        p.setProperty("http3_upstream_hosts", "\\.example\\.com:,^api\\.");
        p.setProperty("http3_max_concurrent_streams", "42");
        p.setProperty("http3_alt_svc", "false");
        DefaultHttpProxyServerBootstrap b = DefaultHttpProxyServerBootstrap.fromProperties(p);
        assertTrue(b.http3);
        assertTrue(b.http3Upstream);
        assertEquals(List.of("\\.example\\.com:", "^api\\."), b.http3UpstreamHosts);
        assertEquals(42, b.http3Options.maxConcurrentStreams());
        assertFalse(b.http3Options.altSvc());
        DefaultHttpProxyServerBootstrap copy = b.copy();
        assertTrue(copy.http3 && copy.http3Upstream);
        assertEquals(b.http3Options, copy.http3Options);
        DefaultHttpProxyServerBootstrap none = DefaultHttpProxyServerBootstrap.fromProperties(new Properties());
        assertFalse(none.http3);
        assertEquals(Http3Options.DEFAULT, none.http3Options);
        assertThrows(IllegalArgumentException.class, () -> MicroProxy.bootstrap().withHttp3UpstreamHosts("("));
    }
}
