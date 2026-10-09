package org.microproxy.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.net.URL;
import java.net.URLClassLoader;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import javax.net.ssl.SSLContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.microproxy.TestSupport;
import org.microproxy.tls.CertificateAuthority;

/**
 * The proxy without the optional {@code http2-codec} module, for real: its classes are loaded by a
 * class loader that sees them and nothing of the codec, and plain and intercepted requests still
 * work, which they would not if any class on their path (and the verifier's) needed the codec.
 * Enabling any kind of HTTP/2 there fails at startup.
 */
class Http2CodecAbsentTest {

    private URLClassLoader isolated;
    private HttpServer origin;
    private HttpServer httpsOrigin;
    private final CertificateAuthority originCa = CertificateAuthority.generate("Codec-Absent Origin CA");

    @BeforeEach
    void setUp() throws Exception {
        // Only the proxy's own classes (target/classes), over the platform class loader.
        URL classes = ClientConnection.class.getProtectionDomain().getCodeSource().getLocation();
        isolated = new URLClassLoader(new URL[] {classes}, ClassLoader.getPlatformClassLoader());
        origin = TestSupport.origin(TestSupport.fixed(200, "plain"));
        httpsOrigin = TestSupport.httpsOrigin(originCa.serverContext("localhost", "127.0.0.1"), TestSupport.fixed(200, "tls"));
    }

    @AfterEach
    void tearDown() throws Exception {
        origin.stop(0);
        httpsOrigin.stop(0);
        isolated.close();
    }

    private Class<?> load(String name) throws ClassNotFoundException {
        return isolated.loadClass(name);
    }

    /** A bootstrap from the isolated classes, with a MITM manager trusting the test origin. */
    private Object bootstrap(Object proxyCa) throws Exception {
        Class<?> bootstrapType = load("org.microproxy.HttpProxyServerBootstrap");
        Object b = load("org.microproxy.MicroProxy").getMethod("bootstrap").invoke(null);
        bootstrapType.getMethod("withPort", int.class).invoke(b, 0);
        Class<?> caType = load("org.microproxy.tls.CertificateAuthority");
        Object mitm = load("org.microproxy.tls.CertificateAuthorityMitmManager")
                .getConstructor(caType, SSLContext.class).newInstance(proxyCa, originCa.clientContext());
        bootstrapType.getMethod("withManInTheMiddle", load("org.microproxy.MitmManager")).invoke(b, mitm);
        return b;
    }

    private Object start(Object bootstrap) throws Exception {
        return load("org.microproxy.HttpProxyServerBootstrap").getMethod("start").invoke(bootstrap);
    }

    @Test
    void theCodecIsInvisibleToTheIsolatedClasses() throws Exception {
        assertThrows(ClassNotFoundException.class, () -> load("io.github.mahmoudimus.http2.FrameReader"));
        Method available = load("org.microproxy.impl.Http2Support").getDeclaredMethod("available");
        available.setAccessible(true);
        assertFalse((Boolean) available.invoke(null));
    }

    @Test
    void plainAndInterceptedRequestsWorkWithoutTheCodec() throws Exception {
        Object proxyCa = load("org.microproxy.tls.CertificateAuthority").getMethod("generate", String.class)
                .invoke(null, "Codec-Absent Proxy CA");
        Object server = start(bootstrap(proxyCa));
        Class<?> serverType = load("org.microproxy.HttpProxyServer");
        try {
            InetSocketAddress address = (InetSocketAddress) serverType.getMethod("getListenAddress").invoke(server);
            SSLContext trust = (SSLContext) proxyCa.getClass().getMethod("clientContext").invoke(proxyCa);
            HttpClient client = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1)
                    .proxy(java.net.ProxySelector.of(address)).sslContext(trust).build();
            HttpResponse<String> plain = TestSupport.get(client, TestSupport.url(origin, "/"));
            assertEquals("plain", plain.body());
            HttpResponse<String> intercepted = TestSupport.get(client, TestSupport.localhostUrl(httpsOrigin, "/"));
            assertEquals("tls", intercepted.body());
        } finally {
            serverType.getMethod("abort").invoke(server);
        }
    }

    @Test
    void enablingHttp2OfAnyKindFailsAtStartup() throws Exception {
        Class<?> bootstrapType = load("org.microproxy.HttpProxyServerBootstrap");
        for (String option : new String[] {"withHttp2", "withHttp2Upstream", "withHttp2Cleartext"}) {
            Object b = load("org.microproxy.MicroProxy").getMethod("bootstrap").invoke(null);
            bootstrapType.getMethod("withPort", int.class).invoke(b, 0);
            bootstrapType.getMethod(option, boolean.class).invoke(b, true);
            InvocationTargetException e = assertThrows(InvocationTargetException.class, () -> start(b));
            assertTrue(e.getCause() instanceof IllegalStateException, option + ": " + e.getCause());
            assertTrue(e.getCause().getMessage().contains("http2-codec"), e.getCause().getMessage());
        }
    }
}
