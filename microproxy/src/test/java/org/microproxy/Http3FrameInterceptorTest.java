package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpsServer;
import io.github.mahmoudimus.http3.HeaderField;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.microproxy.frames.FrameDirection;
import org.microproxy.frames.FrameInterceptor;
import org.microproxy.frames.FrameProtocol;
import org.microproxy.frames.Http3Frame;
import org.microproxy.frames.HttpFrame;
import org.microproxy.tls.CertificateAuthority;
import org.microproxy.tls.CertificateAuthorityMitmManager;
import org.microproxy.tls.SelfSignedSslContextSource;

/**
 * The frame interceptor on live HTTP/3: a client's connection to the reverse proxy's HTTP/3
 * listener and the proxy's connection to an HTTP/3 origin, in all four directions, with edits,
 * drops, additions and the results the rules refuse.
 */
@Timeout(value = 60, unit = TimeUnit.SECONDS)
class Http3FrameInterceptorTest {

    private static CertificateAuthority originCa;
    private static CertificateAuthority proxyCa;

    /** A frame as the interceptor saw it. */
    record Seen(FrameDirection direction, Http3Frame frame, long streamId, boolean hasFlow, String server, long connectionId) {}

    private final List<Seen> seen = new CopyOnWriteArrayList<>();
    private HttpsServer tcp;
    private H3TestOrigin h3;
    private HttpProxyServer proxy;
    private SelfSignedSslContextSource listener;

    @BeforeAll
    static void authorities() {
        originCa = CertificateAuthority.generate("H3 Frames Origin CA");
        proxyCa = CertificateAuthority.generate("H3 Frames Proxy CA");
    }

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.abort();
        if (h3 != null) h3.close();
        if (tcp != null) tcp.stop(0);
    }

    /** A client over HTTP/3 to the proxy, and the proxy over HTTP/3 to the origin, with {@code edit} after recording. */
    private H3TestClient start(FrameInterceptor edit) throws Exception {
        tcp = TestSupport.httpsOrigin(originCa.serverContext("localhost", "127.0.0.1"), TestSupport.fixed(200, "over tcp"));
        h3 = new H3TestOrigin(originCa, tcp.getAddress().getPort());
        listener = new SelfSignedSslContextSource();
        proxy = MicroProxy.bootstrap()
                .withPort(0)
                .withReverseProxy("https://localhost:" + tcp.getAddress().getPort())
                .withSslContextSource(listener)
                .withManInTheMiddle(new CertificateAuthorityMitmManager(proxyCa, originCa.clientContext()))
                .withHttp3(true)
                .withHttp3Upstream(true)
                .withHttp3UpstreamHosts("localhost")
                .withFrameInterceptor((frame, direction, ctx) -> {
                    if (frame instanceof Http3Frame h3frame) {
                        seen.add(new Seen(direction, h3frame, ctx.streamId(), ctx.flowContext() != null, ctx.server(),
                                ctx.connectionId()));
                    }
                    assertEquals(FrameProtocol.HTTP_3, ctx.protocol());
                    return edit.intercept(frame, direction, ctx);
                })
                .start();
        InetSocketAddress address = new InetSocketAddress(TestSupport.LOOPBACK, proxy.getListenAddress().getPort());
        return H3TestClient.connect(address, "localhost", listener.getCertificate());
    }

    private List<Seen> seen(FrameDirection direction, Class<? extends Http3Frame> type) {
        return seen.stream().filter(s -> s.direction() == direction && type.isInstance(s.frame())).toList();
    }

    @Test
    void seesEveryHopInBothDirections() throws Exception {
        try (H3TestClient client = start((frame, direction, ctx) -> frame)) {
            H3TestClient.Response r = client.post("/echo", "ping".getBytes(StandardCharsets.US_ASCII));
            assertEquals(200, r.status());
        }
        for (FrameDirection d : FrameDirection.values()) {
            assertFalse(seen(d, Http3Frame.Settings.class).isEmpty(), "SETTINGS " + d);
            assertFalse(seen(d, Http3Frame.Headers.class).isEmpty(), "HEADERS " + d);
            assertFalse(seen(d, Http3Frame.Data.class).isEmpty(), "DATA " + d);
        }
        Seen fromClient = seen(FrameDirection.FROM_CLIENT, Http3Frame.Headers.class).getFirst();
        assertEquals("/echo", ((Http3Frame.Headers) fromClient.frame()).get(":path"));
        assertEquals(0, fromClient.streamId());
        assertTrue(fromClient.hasFlow(), "an HTTP/3 stream's flow exists before its first frame");
        assertNull(fromClient.server());
        assertTrue(fromClient.connectionId() > 0);
        assertTrue(seen(FrameDirection.FROM_CLIENT, Http3Frame.Data.class).getFirst().hasFlow());
        Seen toServer = seen(FrameDirection.TO_SERVER, Http3Frame.Headers.class).getFirst();
        assertEquals("localhost:" + tcp.getAddress().getPort(), toServer.server());
        assertTrue(toServer.hasFlow());
        assertEquals("200", ((Http3Frame.Headers) seen(FrameDirection.FROM_SERVER, Http3Frame.Headers.class).getFirst().frame())
                .get(":status"));
    }

    @Test
    void editsHeadersAndDataLiveInEveryDirection() throws Exception {
        FrameInterceptor edit = (frame, direction, ctx) -> switch (frame) {
            case Http3Frame.Headers h when direction == FrameDirection.FROM_CLIENT -> h.withHeader("x-from-client", "edited");
            case Http3Frame.Headers h when direction == FrameDirection.TO_SERVER -> h.withHeader("x-to-server", "edited");
            // A longer body: the field that declared the old length goes.
            case Http3Frame.Headers h when direction == FrameDirection.FROM_SERVER && h.get(":status") != null ->
                    h.withoutHeader("content-length").withHeader("x-from-server", "edited");
            case Http3Frame.Data d when direction == FrameDirection.FROM_SERVER -> d.withText(d.text().replace("ping", "PING!!"));
            case Http3Frame.Data d when direction == FrameDirection.TO_CLIENT -> d.withText(d.text().replace("method", "METHOD"));
            case Http3Frame.Headers h when direction == FrameDirection.TO_CLIENT && h.get(":status") != null ->
                    h.withHeader("x-to-client", "edited");
            default -> frame;
        };
        try (H3TestClient client = start(edit)) {
            H3TestClient.Response r = client.post("/echo", "ping".getBytes(StandardCharsets.US_ASCII));
            assertEquals(200, r.status());
            assertEquals("edited", r.header("x-to-client"));
            assertEquals("edited", r.header("x-from-server"));
            assertTrue(r.text().startsWith("METHOD: POST\n"), r.text());
            assertEquals(List.of("edited"), TestSupport.echoedHeader(r.text(), "x-from-client"));
            assertEquals(List.of("edited"), TestSupport.echoedHeader(r.text(), "x-to-server"));
            assertEquals("PING!!", TestSupport.echoedBody(r.text()));
        }
    }

    @Test
    void dropsAddsAndRefusesFramesByTheRules() throws Exception {
        FrameInterceptor edit = (frame, direction, ctx) -> switch (frame) {
            // Extension frames: added and dropped at will.
            case Http3Frame.Headers h when direction == FrameDirection.TO_CLIENT && h.get(":status") != null -> {
                ctx.send(Http3Frame.unknown(0x21, new byte[] {1, 2}));
                yield h;
            }
            case Http3Frame.Unknown u when direction == FrameDirection.FROM_CLIENT -> null;
            // Received SETTINGS may get stricter, never laxer: this is refused, the original used.
            case Http3Frame.Settings s when direction == FrameDirection.FROM_CLIENT ->
                    s.withValue(Http3Frame.SETTINGS_QPACK_MAX_TABLE_CAPACITY, 1 << 20);
            // Sent SETTINGS keep the proxy's own values: refused.
            case Http3Frame.Settings s when direction == FrameDirection.TO_CLIENT ->
                    s.withValue(Http3Frame.SETTINGS_MAX_FIELD_SECTION_SIZE, 1);
            // HEADERS cannot be dropped: refused, passed on unchanged.
            case Http3Frame.Headers h when direction == FrameDirection.TO_SERVER -> null;
            // A throwing interceptor passes the frame on.
            case Http3Frame.Data d when direction == FrameDirection.TO_SERVER -> throw new IllegalStateException("boom");
            default -> frame;
        };
        try (H3TestClient client = start(edit)) {
            assertEquals(4096, client.serverSettings().qpackMaxTableCapacity());
            assertTrue(client.serverSettings().maxFieldSectionSize() > 1);
            H3TestClient.Response r = client.post("/echo", "body".getBytes(StandardCharsets.US_ASCII));
            assertEquals(200, r.status());
            assertEquals("body", TestSupport.echoedBody(r.text()));
            assertEquals(200, client.get("/hello").status());
        }
        HttpFrame clientSettings = seen(FrameDirection.FROM_CLIENT, Http3Frame.Settings.class).getFirst().frame();
        assertNotNull(((Http3Frame.Settings) clientSettings).get(Http3Frame.SETTINGS_QPACK_MAX_TABLE_CAPACITY));
    }

    @Test
    void stricterReceivedSettingsAreApplied() throws Exception {
        // The origin allows a 4096-byte QPACK table; the proxy is told 0, so it encodes without one.
        FrameInterceptor edit = (frame, direction, ctx) -> frame instanceof Http3Frame.Settings s
                && direction == FrameDirection.FROM_SERVER ? s.withValue(Http3Frame.SETTINGS_QPACK_MAX_TABLE_CAPACITY, 0) : frame;
        try (H3TestClient client = start(edit)) {
            for (int i = 0; i < 3; i++) {
                H3TestClient.Response r = client.request("GET", "/echo", List.of(new HeaderField("x-repeat", "same value")),
                        null, List.of());
                assertEquals(List.of("same value"), TestSupport.echoedHeader(r.text(), "x-repeat"));
            }
        }
        assertTrue(h3.errors().isEmpty(), h3.errors().toString());
    }
}
