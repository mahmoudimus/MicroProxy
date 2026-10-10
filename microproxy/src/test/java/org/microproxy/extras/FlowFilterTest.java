package org.microproxy.extras;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.zip.GZIPOutputStream;
import org.junit.jupiter.api.Test;
import org.microproxy.http.DefaultFullHttpRequest;
import org.microproxy.http.DefaultFullHttpResponse;
import org.microproxy.http.DefaultHttpRequest;
import org.microproxy.http.DefaultHttpResponse;
import org.microproxy.http.HttpMethod;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpVersion;

class FlowFilterTest {

    private static final String URL = "https://www.example.com/path/page.html?q=1";

    private static HttpRequest get() {
        HttpRequest r = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "/path/page.html?q=1");
        r.headers().set("Host", "www.example.com");
        r.headers().set("User-Agent", "curl/8.9");
        return r;
    }

    private static HttpRequest post(String body) {
        HttpRequest r = new DefaultFullHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.POST, "/api",
                body.getBytes(StandardCharsets.UTF_8));
        r.headers().set("Host", "api.example.org");
        r.headers().set("Content-Type", "application/json");
        return r;
    }

    private static HttpResponse response(int status, String type, String body) {
        HttpResponse r = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.valueOf(status),
                body.getBytes(StandardCharsets.UTF_8));
        if (type != null) r.headers().set("Content-Type", type);
        r.headers().set("Server", "nginx");
        return r;
    }

    private static boolean matches(String expr, FlowFilter.Flow flow) {
        return FlowFilter.parse(expr).matches(flow);
    }

    private static FlowFilter.Flow request() {
        return FlowFilter.flow(get(), URL, null);
    }

    private static FlowFilter.Flow exchange() {
        return FlowFilter.flow(get(), URL, response(404, "text/html; charset=utf-8", "<p>Not here</p>"));
    }

    @Test
    void urlDomainAndMethod() {
        assertTrue(matches("~u page\\.html", request()));
        assertTrue(matches("page", request()), "a bare regex matches the URL");
        assertTrue(matches("~u PAGE", request()), "case is ignored");
        assertFalse(matches("~u other", request()));
        assertTrue(matches("~d example\\.com$", request()));
        assertFalse(matches("~d example\\.org", request()));
        assertTrue(matches("~m ^GET$", request()));
        assertFalse(matches("~m POST", request()));
    }

    @Test
    void headersAndContentTypes() {
        assertTrue(matches("~h user-agent:\\scurl", request()));
        assertTrue(matches("~hq ^Host: www", request()), "header lines are matched line by line");
        assertFalse(matches("~hs nginx", request()), "no response yet");
        assertTrue(matches("~hs '^server: nginx$'", exchange()));
        assertTrue(matches("~h nginx", exchange()));
        assertTrue(matches("~t text/html", exchange()));
        assertTrue(matches("~ts html", exchange()));
        assertFalse(matches("~tq html", exchange()));
        assertTrue(matches("~tq json", FlowFilter.flow(post("{}"), "http://api.example.org/api", null)));
    }

    @Test
    void requestResponseAndCodes() {
        assertTrue(matches("~q", request()));
        assertFalse(matches("~s", request()));
        assertTrue(matches("~s", exchange()));
        assertFalse(matches("~q", exchange()));
        assertTrue(matches("~c 404", exchange()));
        assertFalse(matches("~c 200", exchange()));
        assertFalse(matches("~c 404", request()));
        assertTrue(matches("~all", request()));
        assertTrue(matches("~a", FlowFilter.flow(get(), URL, response(200, "image/png", ""))));
        assertFalse(matches("~a", exchange()));
    }

    @Test
    void precedenceIsNotThenAndThenOr() {
        FlowFilter.Flow f = request();
        // ! binds tighter than &: (!~m POST) & ~d example
        assertTrue(matches("!~m POST & ~d example", f));
        // & binds tighter than |: ~m POST | (~d nothing & ~u page) is false; (~m POST | ~d nothing) & ~u page too
        assertFalse(matches("~m POST | ~d nothing & ~u page", f));
        assertTrue(matches("~m GET | ~d nothing & ~u nope", f), "GET | (nothing & nope)");
        assertFalse(matches("(~m GET | ~d nothing) & ~u nope", f), "parentheses group");
        assertTrue(matches("!(~m POST | ~d nothing)", f));
        assertFalse(matches("!!~m POST", f));
        assertTrue(matches("!~c 200", f), "no response: ~c is false, so its negation holds");
    }

    @Test
    void juxtapositionIsAnAndWithTheLowestPrecedence() {
        FlowFilter.Flow f = request();
        assertTrue(matches("~m GET ~d example", f));
        assertFalse(matches("~m GET ~d nothing", f));
        // a b | c is a & (b | c), as in mitmproxy.
        assertTrue(matches("~m GET ~d nothing | ~u page", f));
        assertFalse(matches("~m POST ~d nothing | ~u page", f));
    }

    @Test
    void wordsAndQuotedStrings() {
        FlowFilter.Flow f = request();
        assertTrue(matches("~u 'page.html\\?q=1'", f));
        assertTrue(matches("~u \"q=\\d\"", f), "regex escapes survive quotes");
        assertTrue(matches("~h \"User-Agent: curl\"", f), "quotes allow spaces");
        assertTrue(matches("~u nothing|page", f), "| inside a word belongs to the regex");
        assertTrue(matches("~u 'it\\'s' | ~m GET", f));
        assertFalse(matches("~u 'it\\'s'", f));
    }

    @Test
    void bodiesAreDecodedAndLazy() throws IOException {
        FlowFilter.Flow json = FlowFilter.flow(post("{\"user\":\"ünïcode\"}"), "http://api.example.org/api", null);
        assertTrue(matches("~bq ünïcode", json), "UTF-8 bytes match");
        assertTrue(matches("~b USER", json));
        assertFalse(matches("~bs user", json));

        DefaultFullHttpResponse gzipped = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK,
                gzip("secret token inside"));
        gzipped.headers().set("Content-Encoding", "gzip");
        assertTrue(matches("~bs \"secret token\"", FlowFilter.flow(get(), URL, gzipped)));

        // A streamed body is not known: no match yet, but a possible one.
        HttpRequest streamed = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.POST, "/upload");
        streamed.headers().set("Content-Length", "100");
        FlowFilter body = FlowFilter.parse("~m POST & ~bq secret");
        AtomicInteger asked = new AtomicInteger();
        FlowFilter.Flow lazy = new FlowFilter.Flow() {
            @Override
            public HttpRequest request() {
                return streamed;
            }

            @Override
            public String url() {
                return "http://x/upload";
            }

            @Override
            public byte[] requestBody() {
                asked.incrementAndGet();
                return null;
            }
        };
        assertFalse(body.matches(lazy));
        assertTrue(body.mayMatch(lazy));
        assertTrue(body.usesRequestBody());
        assertFalse(body.usesResponseBody());
        // The head alone rules this one out, without asking for the body.
        asked.set(0);
        FlowFilter getOnly = FlowFilter.parse("~m GET & ~bq secret");
        assertFalse(getOnly.mayMatch(lazy));
        assertEquals(0, asked.get(), "the body was never asked for");
        // A request that declares no body has an empty one.
        assertFalse(FlowFilter.parse("~bq x").mayMatch(FlowFilter.flow(get(), URL, null)));
        assertTrue(FlowFilter.parse("!~bq x").matches(FlowFilter.flow(get(), URL, null)));
    }

    @Test
    void negatedUnknownBodiesStayUnknown() {
        HttpResponse streamed = new DefaultHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK);
        streamed.headers().set("Content-Length", "10");
        FlowFilter.Flow f = FlowFilter.flow(get(), URL, streamed);
        FlowFilter notBody = FlowFilter.parse("!~bs x");
        assertFalse(notBody.matches(f));
        assertTrue(notBody.mayMatch(f));
        assertTrue(FlowFilter.parse("~bs x | ~m GET").matches(f), "a known true side decides an or");
        assertFalse(FlowFilter.parse("~bs x & ~m POST").mayMatch(f), "a known false side decides an and");
    }

    @Test
    void invalidExpressionsAreRejected() {
        for (String bad : new String[] {"", "  ", "~x foo", "~d", "(~m GET", "~m GET)", "~c abc", "!", "~u (",
            "~u 'open", "~m GET &", "()", "~u [a"}) {
            assertThrows(IllegalArgumentException.class, () -> FlowFilter.parse(bad), bad);
        }
    }

    @Test
    void specsSplitOnTheirFirstCharacter() {
        Specs.Spec two = Specs.parse("|a|b", 2, "test");
        assertEquals("~all", two.filter().expression());
        Specs.Spec withFilter = Specs.parse("|~d x|a|b|c", 2, "test");
        assertEquals("~d x", withFilter.filter().expression());
        assertEquals(java.util.List.of("a", "b|c"), withFilter.parts());
        assertEquals(java.util.List.of("a", "b"), Specs.parse(":a:b", 2, "test").parts());
        assertThrows(IllegalArgumentException.class, () -> Specs.parse("|a", 2, "test"));
        assertEquals("a\nb\u00e9", new String(Specs.unescape("a\\nb\\xe9"), StandardCharsets.ISO_8859_1));
        assertEquals("$1-${name}-\\\\", Specs.javaReplacement("\\1-\\g<name>-\\\\").replace("\\$", "$"));
    }

    private static byte[] gzip(String s) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (GZIPOutputStream gz = new GZIPOutputStream(out)) {
            gz.write(s.getBytes(StandardCharsets.UTF_8));
        }
        return out.toByteArray();
    }
}
