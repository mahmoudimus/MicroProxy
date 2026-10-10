package org.microproxy.impl;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import org.junit.jupiter.api.Test;
import org.microproxy.ClientDetails;
import org.microproxy.FlowContext;
import org.microproxy.HttpFilters;
import org.microproxy.HttpFiltersChain;
import org.microproxy.HttpFiltersSource;
import org.microproxy.HttpFiltersBuilder.Body;
import org.microproxy.SelectiveFilters;
import org.microproxy.extras.HttpLogger;
import org.microproxy.extras.HttpLogger.Level;
import org.microproxy.http.DefaultHttpRequest;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpMethod;
import org.microproxy.http.HttpResponse;
import org.microproxy.http.HttpVersion;
import org.microproxy.http.WebSocketFrame;

/** Which streams the proxy parses piece by piece for given filters; the rest take the fast path. */
class FastPathDetectionTest {

    private static boolean[] streams(HttpFilters filters) {
        return ClientConnection.inspectedStreams(filters);
    }

    /** Overrides every body and frame hook, so its class alone would turn off every fast path. */
    private static class HeadReader implements HttpFilters {
        @Override
        public HttpResponse clientToProxyRequest(HttpObject httpObject) {
            return null;
        }

        @Override
        public HttpObject serverToProxyResponse(HttpObject httpObject) {
            return httpObject;
        }

        @Override
        public void webSocketFrameReceived(WebSocketFrame frame, boolean fromClient) {}
    }

    /** The same hooks, but it says it only reads heads (and watches frames when asked to). */
    private static final class SelectiveHeadReader extends HeadReader implements SelectiveFilters {
        private final boolean frames;

        SelectiveHeadReader(boolean frames) {
            this.frames = frames;
        }

        @Override
        public boolean sees(Body stream) {
            return frames && stream == Body.OBSERVED_WEBSOCKET_FRAMES;
        }
    }

    @Test
    void classesThatOverrideTheHooksAreAssumedToInspectBodies() {
        assertArrayEquals(new boolean[] {true, true, true}, streams(new HeadReader()));
        assertArrayEquals(new boolean[] {false, false, false}, streams(new HttpFilters() {}));
    }

    @Test
    void selectiveFiltersAreTakenAtTheirWord() {
        assertArrayEquals(new boolean[] {false, false, false}, streams(new SelectiveHeadReader(false)));
        assertArrayEquals(new boolean[] {false, false, true}, streams(new SelectiveHeadReader(true)));
    }

    @Test
    void builtFiltersSeeOnlyWhatTheyRegistered() {
        assertArrayEquals(new boolean[] {false, false, false},
                streams(HttpFilters.builder().onRequest(r -> null).onResponse(r -> r).build()));
        assertArrayEquals(new boolean[] {true, false, false},
                streams(HttpFilters.builder().onRequestBody(p -> {}).build()));
        assertArrayEquals(new boolean[] {false, true, true},
                streams(HttpFilters.builder().onResponseBody(p -> p).onWebSocketFrame((f, c) -> f).build()));
    }

    private static final FlowContext CTX = new FlowContext(1, () -> null, () -> null, new ClientDetails());

    private static HttpFilters filtersFor(HttpFiltersSource source) {
        return source.filterRequest(new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.POST, "/"), CTX);
    }

    private static HttpLogger.Builder logger(Level level) {
        return HttpLogger.builder().level(level).sink(line -> {});
    }

    @Test
    void loggersReadBodiesOnlyAtTheBodyLevel() {
        assertArrayEquals(new boolean[] {false, false, false}, streams(filtersFor(logger(Level.BASIC).build())));
        assertArrayEquals(new boolean[] {false, false, false}, streams(filtersFor(logger(Level.HEADERS).build())));
        assertArrayEquals(new boolean[] {true, true, false}, streams(filtersFor(logger(Level.BODY).build())));
        assertArrayEquals(new boolean[] {true, true, true},
                streams(filtersFor(logger(Level.BODY).webSocketFrames(true).build())));
        // Frames are only logged at BODY.
        assertArrayEquals(new boolean[] {false, false, false},
                streams(filtersFor(logger(Level.HEADERS).webSocketFrames(true).build())));
    }

    @Test
    void loggersKeepTheFastPathInsideChainsAndBuiltFilters() {
        HttpFiltersSource headOnly = HttpFilters.builder().onResponse(r -> r).build();
        assertArrayEquals(new boolean[] {false, false, false},
                streams(filtersFor(HttpFiltersChain.of(logger(Level.HEADERS).build(), headOnly))));
        assertArrayEquals(new boolean[] {true, true, false},
                streams(filtersFor(HttpFiltersChain.of(logger(Level.BODY).build(), headOnly))));
        assertArrayEquals(new boolean[] {false, false, false},
                streams(filtersFor(HttpFilters.builder().log(logger(Level.HEADERS).build()).onRequest(r -> null).build())));
        assertArrayEquals(new boolean[] {true, true, false},
                streams(filtersFor(HttpFilters.builder().log(logger(Level.BODY).build()).build())));
    }

    @Test
    void headAddonsKeepTheFastPath() {
        HttpFiltersSource addons = HttpFiltersChain.of(
                org.microproxy.extras.BlockList.of("|~d ads|404"),
                org.microproxy.extras.AntiCache.create(),
                org.microproxy.extras.MapRemote.of("|example.com|example.net"),
                org.microproxy.extras.MapLocal.of("|/static/|" + System.getProperty("java.io.tmpdir")),
                org.microproxy.extras.ModifyHeaders.of("|X-A|1"),
                org.microproxy.extras.StickyCookie.of("~all"),
                // Buffers the messages it may edit through the buffer hooks; never reads pieces.
                org.microproxy.extras.ModifyBody.of("|a|b"));
        HttpFilters filters = filtersFor(addons);
        assertArrayEquals(new boolean[] {false, false, false}, streams(filters));
        for (HttpFilters member : ((HttpFiltersChain.Chained) filters).members()) {
            assertArrayEquals(new boolean[] {false, false, false}, streams(member), member.getClass().getName());
        }
    }
}
