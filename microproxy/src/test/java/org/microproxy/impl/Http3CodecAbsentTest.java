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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.microproxy.TestSupport;

/**
 * The proxy without the optional {@code quic} module, for real, as {@code Http2CodecAbsentTest}
 * runs it without the HTTP/2 codec: its classes are loaded by a class loader that sees them (and,
 * in one case, {@code http3-codec}) and nothing of QUIC. A reverse proxy and a forward proxy serve
 * requests as before, which they would not if a class on their path needed QUIC, and enabling
 * HTTP/3 either way fails at startup with a message that names the missing modules.
 */
class Http3CodecAbsentTest {

    private URLClassLoader isolated;
    private HttpServer origin;

    @BeforeEach
    void setUp() {
        origin = TestSupport.origin(TestSupport.fixed(200, "plain"));
    }

    @AfterEach
    void tearDown() throws Exception {
        origin.stop(0);
        if (isolated != null) isolated.close();
    }

    private static URL location(Class<?> type) {
        return type.getProtectionDomain().getCodeSource().getLocation();
    }

    /** Only the proxy's own classes, plus {@code extra} class path entries, over the platform class loader. */
    private void isolate(URL... extra) {
        URL[] urls = new URL[extra.length + 1];
        urls[0] = location(ClientConnection.class);
        System.arraycopy(extra, 0, urls, 1, extra.length);
        isolated = new URLClassLoader(urls, ClassLoader.getPlatformClassLoader());
    }

    private Class<?> load(String name) throws ClassNotFoundException {
        return isolated.loadClass(name);
    }

    private Object bootstrap() throws Exception {
        Object b = load("org.microproxy.MicroProxy").getMethod("bootstrap").invoke(null);
        load("org.microproxy.HttpProxyServerBootstrap").getMethod("withPort", int.class).invoke(b, 0);
        return b;
    }

    private Object call(Object bootstrap, String method, Class<?> type, Object arg) throws Exception {
        return load("org.microproxy.HttpProxyServerBootstrap").getMethod(method, type).invoke(bootstrap, arg);
    }

    private Object start(Object bootstrap) throws Exception {
        return load("org.microproxy.HttpProxyServerBootstrap").getMethod("start").invoke(bootstrap);
    }

    @Test
    void neitherModuleIsVisibleAndHttp3SupportSaysSo() throws Exception {
        isolate();
        assertThrows(ClassNotFoundException.class, () -> load("io.github.mahmoudimus.quic.QuicServer"));
        assertThrows(ClassNotFoundException.class, () -> load("io.github.mahmoudimus.http3.QpackEncoder"));
        Method available = load("org.microproxy.impl.Http3Support").getDeclaredMethod("available");
        available.setAccessible(true);
        assertFalse((Boolean) available.invoke(null));
    }

    @Test
    void theCodecAloneIsNotEnough() throws Exception {
        isolate(location(io.github.mahmoudimus.http3.QpackEncoder.class));
        load("io.github.mahmoudimus.http3.QpackEncoder");
        assertThrows(ClassNotFoundException.class, () -> load("io.github.mahmoudimus.quic.QuicServer"));
        Method available = load("org.microproxy.impl.Http3Support").getDeclaredMethod("available");
        available.setAccessible(true);
        assertFalse((Boolean) available.invoke(null));
    }

    @Test
    void reverseAndForwardProxiesServeWithoutQuic() throws Exception {
        isolate();
        Class<?> serverType = load("org.microproxy.HttpProxyServer");
        Object reverse = bootstrap();
        call(reverse, "withReverseProxy", String.class, "http://127.0.0.1:" + origin.getAddress().getPort());
        Object reverseServer = start(reverse);
        Object forwardServer = start(bootstrap());
        try {
            InetSocketAddress r = (InetSocketAddress) serverType.getMethod("getListenAddress").invoke(reverseServer);
            String raw = TestSupport.rawExchange(r, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
            assertTrue(raw.startsWith("HTTP/1.1 200"), raw);
            assertTrue(raw.endsWith("plain"), raw);
            assertFalse(raw.toLowerCase(java.util.Locale.ROOT).contains("alt-svc"), raw);
            InetSocketAddress f = (InetSocketAddress) serverType.getMethod("getListenAddress").invoke(forwardServer);
            HttpClient client = HttpClient.newBuilder().proxy(java.net.ProxySelector.of(f)).build();
            assertEquals("plain", TestSupport.get(client, TestSupport.url(origin, "/")).body());
        } finally {
            serverType.getMethod("abort").invoke(reverseServer);
            serverType.getMethod("abort").invoke(forwardServer);
        }
    }

    @Test
    void enablingHttp3EitherWayFailsAtStartup() throws Exception {
        isolate(location(io.github.mahmoudimus.http3.QpackEncoder.class));
        Object served = bootstrap();
        call(served, "withReverseProxy", String.class, "http://127.0.0.1:" + origin.getAddress().getPort());
        call(served, "withHttp3", boolean.class, true);
        Object upstream = bootstrap();
        call(upstream, "withHttp3Upstream", boolean.class, true);
        for (Object b : new Object[] {served, upstream}) {
            InvocationTargetException e = assertThrows(InvocationTargetException.class, () -> start(b));
            assertTrue(e.getCause() instanceof IllegalStateException, String.valueOf(e.getCause()));
            assertTrue(e.getCause().getMessage().contains("io.github.mahmoudimus:quic"), e.getCause().getMessage());
        }
    }
}
