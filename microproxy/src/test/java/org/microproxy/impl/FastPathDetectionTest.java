package org.microproxy.impl;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import org.junit.jupiter.api.Test;
import org.microproxy.HttpFilters;
import org.microproxy.HttpFiltersBuilder.Body;
import org.microproxy.SelectiveFilters;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpResponse;
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
}
