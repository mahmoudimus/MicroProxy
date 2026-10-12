package org.microproxy.extras;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.microproxy.HttpFilters;
import org.microproxy.http.DefaultFullHttpRequest;
import org.microproxy.http.FullHttpRequest;
import org.microproxy.http.FullHttpResponse;
import org.microproxy.http.HttpMethod;
import org.microproxy.http.HttpResponse;
import org.microproxy.http.HttpVersion;

/** Matching, use and refreshing of {@link ServerReplay}, without a proxy. */
class ServerReplayTest {

    private static final Instant RECORDED = Instant.parse("2020-01-01T00:00:00Z");

    /** A recorded exchange; {@code requestHeaders} are names and values, alternately. */
    private static RecordedExchange recorded(String method, String url, String requestBody, String responseBody,
            String... requestHeaders) {
        return new RecordedExchange(RECORDED, method, url, pairs(requestHeaders),
                requestBody.getBytes(StandardCharsets.UTF_8), 200, "OK",
                List.of(Map.entry("Content-Type", "text/plain"), Map.entry("Content-Length", "999"),
                        Map.entry("Connection", "close")),
                responseBody.getBytes(StandardCharsets.UTF_8), true);
    }

    private static List<Map.Entry<String, String>> pairs(String... namesAndValues) {
        List<Map.Entry<String, String>> out = new java.util.ArrayList<>();
        for (int i = 0; i + 1 < namesAndValues.length; i += 2) out.add(Map.entry(namesAndValues[i], namesAndValues[i + 1]));
        return out;
    }

    private static String ask(ServerReplay replay, String method, String uri, String body, String... headers) {
        HttpResponse r = response(replay, method, uri, body, headers);
        return r == null ? null : new String(((FullHttpResponse) r).content(), StandardCharsets.UTF_8);
    }

    private static HttpResponse response(ServerReplay replay, String method, String uri, String body,
            String... headers) {
        FullHttpRequest request = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.valueOf(method), uri,
                body.getBytes(StandardCharsets.UTF_8));
        for (Map.Entry<String, String> h : pairs(headers)) request.headers().add(h.getKey(), h.getValue());
        HttpFilters f = replay.filterRequest(request, null);
        return f.clientToProxyRequest(request);
    }

    @Test
    void matchesOnMethodSchemeHostPortPathQueryAndBody() {
        ServerReplay replay = ServerReplay.builder().reuse(true).add(List.of(
                recorded("GET", "http://example.com/a?x=1&y=2", "", "a"),
                recorded("POST", "http://example.com/a?x=1&y=2", "body", "posted"),
                recorded("GET", "https://example.com:8443/a", "", "tls"))).build();
        assertEquals("a", ask(replay, "GET", "http://example.com/a?x=1&y=2", ""));
        assertEquals("a", ask(replay, "GET", "http://example.com:80/a?x=1&y=2", ""), "the default port");
        assertNull(ask(replay, "GET", "http://example.com/a?y=2&x=1", ""), "parameter order counts");
        assertNull(ask(replay, "GET", "http://example.org/a?x=1&y=2", ""));
        assertNull(ask(replay, "GET", "http://example.com:81/a?x=1&y=2", ""));
        assertNull(ask(replay, "GET", "http://example.com/b?x=1&y=2", ""));
        assertEquals("posted", ask(replay, "POST", "http://example.com/a?x=1&y=2", "body"));
        assertNull(ask(replay, "POST", "http://example.com/a?x=1&y=2", "other body"));
        assertEquals("tls", ask(replay, "GET", "https://example.com:8443/a", ""));
        assertNull(ask(replay, "GET", "http://example.com:8443/a", ""), "the scheme counts");
    }

    @Test
    void ignoreOptionsLooseTheMatch() {
        List<RecordedExchange> flows = List.of(
                recorded("POST", "http://example.com/a?x=1&_=123", "user=bob&nonce=1", "loose"));
        assertEquals("loose", ask(ServerReplay.builder().add(flows).ignoreParams("_").build(),
                "POST", "http://example.com/a?x=1&_=999", "user=bob&nonce=1"));
        assertEquals("loose", ask(ServerReplay.builder().add(flows).ignoreParams("_").ignoreContent(true).build(),
                "POST", "http://example.com/a?x=1", "anything"));
        assertEquals("loose", ask(ServerReplay.builder().add(flows).ignoreParams("_").ignoreHost(true).ignorePort(true)
                .build(), "POST", "http://other.test:8080/a?x=1", "user=bob&nonce=1"));
        RecordedExchange form = recorded("POST", "http://example.com/f", "user=bob&nonce=1", "form",
                "Content-Type", "application/x-www-form-urlencoded");
        assertEquals("form", ask(ServerReplay.builder().add(List.of(form)).ignorePayloadParams("nonce").build(),
                "POST", "http://example.com/f", "user=bob&nonce=2",
                "Content-Type", "application/x-www-form-urlencoded"));
        assertNull(ask(ServerReplay.builder().add(List.of(form)).ignorePayloadParams("nonce").build(),
                "POST", "http://example.com/f", "user=eve&nonce=2",
                "Content-Type", "application/x-www-form-urlencoded"));
    }

    @Test
    void useHeadersMakesHeadersPartOfTheMatch() {
        ServerReplay replay = ServerReplay.builder().useHeaders("Accept").add(List.of(
                recorded("GET", "http://e.test/", "", "json", "Accept", "application/json"),
                recorded("GET", "http://e.test/", "", "html", "Accept", "text/html"))).build();
        assertEquals("html", ask(replay, "GET", "http://e.test/", "", "accept", "text/html"));
        assertEquals("json", ask(replay, "GET", "http://e.test/", "", "Accept", "application/json"));
        assertNull(ask(replay, "GET", "http://e.test/", ""));
    }

    @Test
    void recordingsAreUsedUpInOrderUnlessReused() {
        List<RecordedExchange> flows = List.of(recorded("GET", "http://e.test/n", "", "1"),
                recorded("GET", "http://e.test/n", "", "2"));
        ServerReplay once = ServerReplay.builder().add(flows).build();
        assertEquals(2, once.remaining());
        assertEquals("1", ask(once, "GET", "http://e.test/n", ""));
        assertEquals("2", ask(once, "GET", "http://e.test/n", ""));
        assertNull(ask(once, "GET", "http://e.test/n", ""));
        assertEquals(0, once.remaining());
        ServerReplay reused = ServerReplay.builder().add(flows).reuse(true).build();
        for (int i = 0; i < 3; i++) assertEquals("1", ask(reused, "GET", "http://e.test/n", ""));
    }

    @Test
    void extraRequestsAreForwardedKilledOrAnswered() {
        List<RecordedExchange> flows = List.of(recorded("GET", "http://e.test/", "", "x"));
        assertNull(response(ServerReplay.builder().add(flows).build(), "GET", "http://e.test/other", ""));
        HttpResponse status = response(ServerReplay.builder().add(flows).extra(ServerReplay.Extra.parse("404")).build(),
                "GET", "http://e.test/other", "");
        assertEquals(404, status.status().code());
        assertInstanceOf(ServerReplay.Replayed.class, status);

        ServerReplay kill = ServerReplay.builder().add(flows).extra(ServerReplay.Extra.kill()).build();
        FullHttpRequest request = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "http://e.test/o");
        HttpFilters f = kill.filterRequest(request, null);
        HttpResponse placeholder = f.clientToProxyRequest(request);
        assertNull(f.proxyToClientResponse(placeholder), "the connection is closed instead");
        assertThrows(IllegalArgumentException.class, () -> ServerReplay.Extra.parse("sometimes"));
    }

    @Test
    void replayedResponsesAreFramedByTheProxyAndRefreshed() {
        RecordedExchange e = new RecordedExchange(RECORDED, "GET", "http://e.test/", List.of(), new byte[0], 200, "OK",
                List.of(Map.entry("Date", "Wed, 01 Jan 2020 00:00:00 GMT"),
                        Map.entry("Expires", "Wed, 01 Jan 2020 01:00:00 GMT"),
                        Map.entry("Set-Cookie", "a=1; Path=/; Expires=Thu, 02 Jan 2020 00:00:00 GMT; HttpOnly"),
                        Map.entry("Transfer-Encoding", "chunked"), Map.entry("Keep-Alive", "timeout=5")),
                "body".getBytes(StandardCharsets.UTF_8), true);
        Clock later = Clock.fixed(RECORDED.plus(Duration.ofDays(10)), ZoneOffset.UTC);
        HttpResponse r = response(ServerReplay.builder().add(List.of(e)).clock(later).build(), "GET", "http://e.test/", "");
        assertEquals("Sat, 11 Jan 2020 00:00:00 GMT", r.headers().get("Date"));
        assertEquals("Sat, 11 Jan 2020 01:00:00 GMT", r.headers().get("Expires"));
        assertEquals("a=1; Path=/; Expires=Sun, 12 Jan 2020 00:00:00 GMT; HttpOnly", r.headers().get("Set-Cookie"));
        assertNull(r.headers().get("Transfer-Encoding"));
        assertNull(r.headers().get("Keep-Alive"));
        assertEquals("4", r.headers().get("Content-Length"));
        HttpResponse unrefreshed = response(ServerReplay.builder().add(List.of(e)).refresh(false).build(),
                "GET", "http://e.test/", "");
        assertEquals("Wed, 01 Jan 2020 00:00:00 GMT", unrefreshed.headers().get("Date"));
    }

    @Test
    void incompleteRecordingsAreNotReplayed() {
        RecordedExchange cut = new RecordedExchange(RECORDED, "GET", "http://e.test/", List.of(), new byte[0], 200, "OK",
                List.of(), "partial".getBytes(StandardCharsets.UTF_8), false);
        RecordedExchange none = new RecordedExchange(RECORDED, "GET", "http://e.test/x", List.of(), new byte[0], 0, "",
                List.of(), new byte[0], true);
        ServerReplay replay = ServerReplay.builder().add(List.of(cut, none)).build();
        assertEquals(0, replay.remaining());
    }
}
