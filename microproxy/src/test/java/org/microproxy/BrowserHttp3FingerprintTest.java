package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpsServer;
import java.io.ByteArrayInputStream;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.frames.FrameDirection;
import org.microproxy.frames.FrameInterceptor;
import org.microproxy.frames.Http3Frame;
import org.microproxy.tls.BrowserProfile;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;

/**
 * With {@link Http3Options.Builder#upstreamProfile} set to Chrome 156, the proxy's HTTP/3
 * connection to a server opens as Chrome 156's does (quic/src/test/resources/fingerprints/chrome-156-quic):
 * its SETTINGS in Chrome's order and values, then a GREASE setting; a GREASE frame; no QPACK streams
 * up front; and the request with Chrome's pseudo-header order and a PRIORITY_UPDATE for its priority.
 */
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class BrowserHttp3FingerprintTest {

    private final CertificateAuthority originCa = CertificateAuthority.generate("H3 Fingerprint Origin CA");
    private final CertificateAuthority proxyCa = CertificateAuthority.generate("H3 Fingerprint Proxy CA");
    private H3TestOrigin h3;
    private HttpsServer tcp;
    private HttpProxyServer proxy;

    @AfterEach
    void stop() throws Exception {
        if (proxy != null) proxy.abort();
        if (h3 != null) h3.close();
        if (tcp != null) tcp.stop(0);
    }

    private static Map<Long, Long> settings(byte[] payload) throws Exception {
        Map<Long, Long> out = new LinkedHashMap<>();
        ByteArrayInputStream in = new ByteArrayInputStream(payload);
        while (in.available() > 0) {
            out.put(io.github.mahmoudimus.http3.QuicVarInt.read(in), io.github.mahmoudimus.http3.QuicVarInt.read(in));
        }
        return out;
    }

    private static boolean reserved(long id) {
        return id >= 0x21 && (id - 0x21) % 0x1f == 0;
    }

    @Test
    void theHttp3ConnectionToTheServerOpensAsChromes() throws Exception {
        // CaptureH3 advertises empty SETTINGS: neither dynamic QPACK nor extended CONNECT.
        h3 = new H3TestOrigin(originCa, 0, false, 0, 0);
        h3.extendedConnect = false;
        h3.settingsMarker = true;
        try (SettingsOrder order = new SettingsOrder(true)) {
            requestOverChrome(order.interceptor());
            assertEquals(Map.of(), order.receivedSettings);
        }

        // the control stream first, and no QPACK streams yet (Chrome opens them when it needs them)
        assertEquals(List.of(0L), h3.uniStreamTypes);
        Map.Entry<Long, byte[]> first = h3.controlFrames.get(0);
        assertEquals(0x4L, first.getKey());
        List<Map.Entry<Long, Long>> sent = List.copyOf(settings(first.getValue()).entrySet());
        assertEquals(List.of(Map.entry(0x1L, 65_536L), Map.entry(0x6L, 262_144L), Map.entry(0x7L, 100L), Map.entry(0x33L, 1L)),
                sent.subList(0, 4));
        assertEquals(5, sent.size());
        assertTrue(reserved(sent.get(4).getKey()), "GREASE setting 0x" + Long.toHexString(sent.get(4).getKey()));
        assertTrue(reserved(h3.controlFrames.get(1).getKey()), "GREASE frame");
        Map.Entry<Long, byte[]> priority = h3.controlFrames.get(2);
        assertEquals(0xf0700L, priority.getKey());
        // stream 0, then the request's priority (Chrome's navigation one, from the profile's headers)
        assertEquals("u=0, i", new String(priority.getValue(), 1, priority.getValue().length - 1, StandardCharsets.US_ASCII));
        assertEquals(List.of(":method", ":authority", ":scheme", ":path"), h3.requestFieldNames.get(0).subList(0, 4));
    }

    @Test
    void chromeOpensItsQpackEncoderWhenDynamicSettingsPrecedeTheFirstRequest() throws Exception {
        h3 = new H3TestOrigin(originCa, 0);
        h3.settingsMarker = true;
        try (SettingsOrder order = new SettingsOrder(true)) {
            requestOverChrome(order.interceptor());
            assertEquals(4096L, order.receivedSettings.get(Http3Frame.SETTINGS_QPACK_MAX_TABLE_CAPACITY));
            assertEquals(16L, order.receivedSettings.get(Http3Frame.SETTINGS_QPACK_BLOCKED_STREAMS));
        }
        assertEquals(Set.of(0L, 2L), Set.copyOf(h3.uniStreamTypes));
    }

    @Test
    void chromeKeepsOnlyItsControlStreamWhenDynamicSettingsFollowTheFirstRequest() throws Exception {
        h3 = new H3TestOrigin(originCa, 0);
        h3.settingsMarker = true;
        try (SettingsOrder order = new SettingsOrder(false)) {
            requestOverChrome(order.interceptor());
            await(order.settingsApplied, "SETTINGS applied after the first request");
        }
        assertEquals(List.of(0L), h3.uniStreamTypes);
    }

    private void requestOverChrome(FrameInterceptor interceptor) throws Exception {
        tcp = TestSupport.httpsOrigin(originCa.serverContext("localhost", "127.0.0.1"), exchange -> {
            exchange.getRequestBody().readAllBytes();
            byte[] out = "over tcp".getBytes(StandardCharsets.US_ASCII);
            exchange.getResponseHeaders().set("Alt-Svc", "h3=\":" + h3.port() + "\"; ma=60");
            exchange.sendResponseHeaders(200, out.length);
            exchange.getResponseBody().write(out);
            exchange.close();
        });
        BrowserProfile chrome = BrowserProfile.chrome156();
        proxy = MicroProxy.bootstrap()
                .withPort(0)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .withHttp3Upstream(true)
                .withHttp3Options(Http3Options.builder().upstreamProfile(chrome).build())
                .withFiltersSource(chrome.filtersSource(true))
                .withFrameInterceptor(interceptor)
                .start();
        HttpClient client = TestSupport.client(proxy, proxyCa.clientContext());
        String url = TestSupport.localhostUrl(tcp, "/hello");
        assertEquals("over tcp", TestSupport.get(client, url).body());
        HttpResponse<String> second = TestSupport.get(client, url);
        assertEquals("hello over h3", second.body());
        assertTrue(h3.errors().isEmpty(), h3.errors().toString());
    }

    private static void await(CountDownLatch latch, String description) {
        try {
            assertTrue(latch.await(10, TimeUnit.SECONDS), description);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AssertionError(description, e);
        }
    }

    /** Orders SETTINGS application against the real encoder, without depending on packet scheduling. */
    private static final class SettingsOrder implements AutoCloseable {
        final boolean settingsFirst;
        final CountDownLatch settingsReceived = new CountDownLatch(1);
        final CountDownLatch settingsApplied = new CountDownLatch(1);
        final CountDownLatch requestDecoded = new CountDownLatch(1);
        volatile Map<Long, Long> receivedSettings;

        SettingsOrder(boolean settingsFirst) {
            this.settingsFirst = settingsFirst;
        }

        FrameInterceptor interceptor() {
            return (frame, direction, ctx) -> {
                if (frame instanceof Http3Frame.Settings s && direction == FrameDirection.FROM_SERVER) {
                    receivedSettings = s.values();
                    settingsReceived.countDown();
                    if (!settingsFirst) await(requestDecoded, "first request decoded before applying SETTINGS");
                } else if (frame instanceof Http3Frame.Unknown u && direction == FrameDirection.FROM_SERVER
                        && u.type() == H3TestOrigin.SETTINGS_MARKER) {
                    // readControl applies SETTINGS before reading the next control frame. Its SETTINGS
                    // interceptor alone would only prove receipt, before applyPeerSettings runs.
                    settingsApplied.countDown();
                } else if (frame instanceof Http3Frame.Headers && direction == FrameDirection.TO_SERVER) {
                    // Http3MessageWriter calls this hook before encodeFields.
                    await(settingsFirst ? settingsApplied : settingsReceived, "peer SETTINGS reached the ordered point");
                } else if (frame instanceof Http3Frame.Headers && direction == FrameDirection.FROM_SERVER) {
                    // A response proves that the origin decoded the first request.
                    requestDecoded.countDown();
                }
                return frame;
            };
        }

        @Override
        public void close() {
            settingsReceived.countDown();
            settingsApplied.countDown();
            requestDecoded.countDown();
        }
    }

    @Test
    void theHttp3ConnectionToTheServerOpensAsFirefoxs() throws Exception {
        h3 = new H3TestOrigin(originCa, 0);
        tcp = TestSupport.httpsOrigin(originCa.serverContext("localhost", "127.0.0.1"), exchange -> {
            exchange.getRequestBody().readAllBytes();
            byte[] out = "over tcp".getBytes(StandardCharsets.US_ASCII);
            exchange.getResponseHeaders().set("Alt-Svc", "h3=\":" + h3.port() + "\"; ma=60");
            exchange.sendResponseHeaders(200, out.length);
            exchange.getResponseBody().write(out);
            exchange.close();
        });
        BrowserProfile firefox = BrowserProfile.firefox159();
        proxy = MicroProxy.bootstrap()
                .withPort(0)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .withHttp3Upstream(true)
                .withHttp3Options(Http3Options.builder().upstreamProfile(firefox).build())
                .withFiltersSource(firefox.filtersSource(true))
                .start();
        HttpClient client = TestSupport.client(proxy, proxyCa.clientContext());
        String url = TestSupport.localhostUrl(tcp, "/hello");
        assertEquals("over tcp", TestSupport.get(client, url).body());
        HttpResponse<String> second = TestSupport.get(client, url);
        assertEquals("hello over h3", second.body());
        assertTrue(h3.errors().isEmpty(), h3.errors().toString());

        // the control stream and both QPACK streams at once, as Firefox opens them
        assertEquals(java.util.Set.of(0L, 2L, 3L), java.util.Set.copyOf(h3.uniStreamTypes));
        Map.Entry<Long, byte[]> first = h3.controlFrames.get(0);
        assertEquals(0x4L, first.getKey());
        // quic/src/test/resources/fingerprints/firefox-159-quic/h3-control-and-request-0.txt: no GREASE setting
        assertEquals(List.of(Map.entry(0x1L, 65_536L), Map.entry(0x7L, 20L), Map.entry(0x2b603742L, 0L),
                Map.entry(0xffd277L, 1L), Map.entry(0x33L, 1L), Map.entry(0x8L, 1L)),
                List.copyOf(settings(first.getValue()).entrySet()));
        assertTrue(reserved(h3.controlFrames.get(1).getKey()), "GREASE frame");
        // no PRIORITY_UPDATE: Firefox's priority is in the request's priority field alone
        assertEquals(2, h3.controlFrames.size(), h3.controlFrames.toString());
        List<String> names = h3.requestFieldNames.get(0);
        assertEquals(List.of(":method", ":scheme", ":authority", ":path", "user-agent", "accept", "accept-language",
                "alt-used", "upgrade-insecure-requests"), names.subList(0, 9));
    }
}
