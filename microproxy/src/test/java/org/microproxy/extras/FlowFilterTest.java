package org.microproxy.extras;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
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

    private static FlowFilter.Flow at(String url) {
        return FlowFilter.flow(get(), url, null);
    }

    @Test
    void urlRulesSeeTheNormalizedUrlSoEscapesAndDefaultPortsCannotSlipPastADeny() {
        // Percent-escapes of unreserved characters are decoded: /%61ds/ is /ads/ to the origin.
        assertTrue(matches("~u /ads/", at("http://example.com/%61ds/x")));
        assertTrue(matches("~u /ads/", at("http://example.com/a%64%73/x")));
        assertTrue(matches("~u \"/a-b_c\\\\.d~e\"", at("http://example.com/a%2Db%5Fc%2Ed%7Ee")));
        assertTrue(matches("/ads/", at("http://example.com/%61ds/x")), "a bare regex is a URL rule too");
        // The default port of the scheme is dropped; the host is lower case.
        assertTrue(matches("~u ^https://example\\.com/", at("https://example.com:443/x")));
        assertTrue(matches("~u ^http://example\\.com/", at("http://example.com:80/x")));
        assertTrue(matches("~u ^https://example\\.com/", at("HTTPS://Example.COM:443/x")));
        assertTrue(matches("~u ^https://\\[::1\\]/", at("https://[::1]:443/x")));
        // The proxy routes on the host after the last @: user info is not part of the URL rules see.
        assertTrue(matches("~u ^https://example\\.com/", at("https://u@example.com:443/x")));
        assertTrue(matches("~u ^http://example\\.com/", at("http://a:b@example.com/x")));
        assertFalse(matches("~u ^http://example\\.com", at("http://example.com:80@evil.test/x")),
                "the host is evil.test, whatever comes before the @");
        // Ports as the proxy parses them: :080, :+80 and an empty port are port 80.
        assertTrue(matches("~u ^http://example\\.com/", at("http://example.com:080/x")));
        assertTrue(matches("~u ^http://example\\.com/", at("http://example.com:+80/x")));
        assertTrue(matches("~u ^http://example\\.com/", at("http://example.com:/x")));
        assertTrue(matches("~u ^https://example\\.com:8443/", at("https://example.com:08443/x")));
        // A trailing dot names the same host.
        assertTrue(matches("~u ^https://example\\.com/", at("https://example.com./x")));
        assertTrue(matches("~u ^https://example\\.com/", at("https://example.com.:443/x")));
        // Dot segments, escaped or not, are resolved as the origin resolves them.
        assertTrue(matches("~u ^https://example\\.com/admin", at("https://example.com/./admin")));
        assertTrue(matches("~u ^https://example\\.com/admin", at("https://example.com/x/../admin")));
        assertTrue(matches("~u ^https://example\\.com/admin", at("https://example.com/x/%2E%2E/admin")));
        assertTrue(matches("~u ^https://example\\.com/admin", at("https://example.com/%2e/admin")));
        assertTrue(matches("~u ^https://example\\.com/admin\\?q=/\\.\\./", at("https://example.com/admin?q=/../")),
                "only the path is resolved");
        // Other ports, and escapes of reserved or non-ASCII bytes, are kept.
        assertTrue(matches("~u ^https://example\\.com:8443/", at("https://example.com:8443/x")));
        assertTrue(matches("~u ^http://example\\.com:443/", at("http://example.com:443/x")));
        assertTrue(matches("~u /a%2Fb", at("http://example.com/a%2Fb")));
        assertFalse(matches("~u /a/b", at("http://example.com/a%2Fb")));
        assertTrue(matches("~u q=%26", at("http://example.com/?q=%26")));
        // Malformed escapes are left as they are.
        assertTrue(matches("~u /%6g%", at("http://example.com/%6g%")));
    }

    @Test
    void anOriginFormRequestIsNormalizedFromItsHostHeader() {
        HttpRequest r = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "/%61ds/../ads/x");
        r.headers().set("Host", "EXAMPLE.com:080");
        FlowFilter.Flow flow = FlowFilter.flow(r, RewriteRules.absoluteUrl(r, null), null);
        assertTrue(matches("~u ^http://example\\.com/ads/x$", flow));
    }

    @Test
    void longDotSegmentRunsNormalizeInLinearTime() {
        String path = "/a/..".repeat(200_000) + "/x";
        long started = System.nanoTime();
        assertEquals("http://example.com/x", FlowFilter.normalizedUrl("http://example.com" + path));
        assertTrue(System.nanoTime() - started < 10_000_000_000L, "linear: a 1 MB path takes milliseconds; quadratic copying would take minutes");
    }

    @Test
    void rulesWrittenForTheOldSpellingAreFlagged() {
        assertTrue(FlowFilter.looksStale("/%61ds/"));
        assertTrue(FlowFilter.looksStale("%2e%2e"));
        assertTrue(FlowFilter.looksStale("^https://example\\.com:443/"));
        assertTrue(FlowFilter.looksStale("^http://example\\.com:80$"));
        assertTrue(FlowFilter.looksStale("^https://[^/]*@"));
        assertTrue(FlowFilter.looksStale("/\\.\\./"));
        assertTrue(FlowFilter.looksStale("\\.\\./"));
        assertTrue(FlowFilter.looksStale("/\\.\\.$"));
        assertTrue(FlowFilter.looksStale("/\\.\\.(/|$)"));
        assertTrue(FlowFilter.looksStale("/../"));
        // Still live: a non-default port, ports that only start with 80/443, other escapes.
        assertFalse(FlowFilter.looksStale("^http://example\\.com:443/"));
        assertFalse(FlowFilter.looksStale("^https://example\\.com:80/"));
        assertFalse(FlowFilter.looksStale("^http://example\\.com:8080/"));
        assertFalse(FlowFilter.looksStale("^http://example\\.com:80\\d\\d/"));
        assertFalse(FlowFilter.looksStale("^https://example\\.com:443[0-9]/"));
        assertFalse(FlowFilter.looksStale("/a%2Fb"));
        assertFalse(FlowFilter.looksStale("/ads/"));
        assertFalse(FlowFilter.looksStale("\\.(js|css)$"));
        assertFalse(FlowFilter.looksStale("/\\.(git|env)"));
        assertFalse(FlowFilter.looksStale("/\\."));
        assertTrue(FlowFilter.looksStale("/\\./"));
        assertTrue(FlowFilter.looksStale("^https://[^/]+:443/"));
        assertFalse(FlowFilter.looksStale("^https://example\\.com/a@b"), "an @ in the path is not user info");
        assertFalse(FlowFilter.looksStale("page\\.html"));
    }

    @Test
    void aDomainRuleIgnoresATrailingDot() {
        assertTrue(matches("~d ^example\\.com$", at("https://example.com./x")));
        HttpRequest r = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "/x");
        r.headers().set("Host", "example.com.:443");
        assertTrue(matches("~d ^example\\.com$", FlowFilter.flow(r, "https://other.test/x", null)));
    }

    @Test
    void decodeQuery() {
        assertEquals("https://e.test/dl?file=/files/x", FlowFilter.decodeQuery("https://e.test/dl?file=%2Ffiles%2Fx", false, false));
        assertEquals("https://e.test/?q=é&r=%", FlowFilter.decodeQuery("https://e.test/?q=%C3%A9&r=%", false, false));
        assertEquals("https://e.test/?q=\uFFFD", FlowFilter.decodeQuery("https://e.test/?q=%C3", false, false), "malformed UTF-8 is replaced");
        assertEquals("https://e.test/a%2Fb?x=/#f/", FlowFilter.decodeQuery("https://e.test/a%2Fb?x=%2F#f%2F", false, false),
                "the path is not decoded; everything after ? is");
        assertEquals("https://e.test/?cmd=rm+-rf", FlowFilter.decodeQuery("https://e.test/?cmd=rm+-rf", false, false));
        assertEquals("https://e.test/?cmd=rm -rf", FlowFilter.decodeQuery("https://e.test/?cmd=rm+-rf", true, false), "+ as a space");
        assertEquals("https://e.test/?n=a\nb\u0085c", FlowFilter.decodeQuery("https://e.test/?n=a%0ab%c2%85c", false, false),
                "decoded controls are left as the origin sees them");
        assertEquals("https://e.test/a%2Fb", FlowFilter.decodeQuery("https://e.test/a%2Fb", true, false));
        assertEquals(List.of(), FlowFilter.queryDecoded(at("https://e.test/dl?file=/x")), "nothing to decode");
        assertEquals(1, FlowFilter.queryDecoded(at("https://e.test/dl?file=%2Fx")).size(), "no + : one form");
        assertEquals(2, FlowFilter.queryDecoded(at("https://e.test/dl?file=%2Fx+y")).size());
        assertEquals(4, FlowFilter.queryDecoded(at("https://e.test/dl?file=%2Fx%26y+z")).size());
        assertEquals("https://e.test/?f=/a%26b%3Dc%23d%3Be", FlowFilter.decodeQuery("https://e.test/?f=%2Fa%26b%3Dc%23d%3Be", false, true),
                "delimiters stay escaped");
    }

    @Test
    void aLineTerminatorInTheUrlCannotSatisfyAnAnchor() {
        // U+0085 arrives as the raw byte 0x85 (ISO-8859-1); java.util.regex treats it as a line end.
        assertFalse(matches("~u ^http://good\\.example/", at("http://evil.test/?\u0085http://good.example/")));
        assertFalse(matches("~u ^https://e\\.test/dl\\?file=/ok$", at("https://e.test/dl?file=/ok\u0085&admin=1")));
        assertFalse(matches("~u ^https://e\\.test/ok$", at("https://e.test/ok\u2028x")));
        assertEquals("https://e.test/a%85b", FlowFilter.normalizedUrl("https://e.test/a\u0085b"));
    }

    @Test
    void theDecodedViewCoversFragmentsPlusAndEscapedNewlines() {
        assertTrue(blocks("~u [?&]file=/files/x", "https://e.test/get?a=1#&file=%2Ffiles%2Fx"));
        assertTrue(blocks("~u [?&]next=//.*evil\\.example", "https://e.test/?next=%2F%2Fx%0Aevil.example"));
        assertTrue(blocks("~u \"[?&]cmd=rm -rf\"", "https://e.test/?cmd=rm+-rf"));
        assertTrue(blocks("~u \"[?&]cmd=rm -rf\"", "https://e.test/?cmd=rm%20-rf"));
    }

    @Test
    void decodingNeverMakesADenyMatchLess() {
        // A literal + next to an escape: one server keeps +, another reads it as a space.
        assertTrue(blocks("~u tag=c\\+\\+", "https://e.test/?tag=c%2B+"));
        assertTrue(blocks("~u tag=c\\+\\+", "https://e.test/?a=%2F&tag=c++"));
        // Decoded controls stay raw, so \\s, . and [^&] see the tab or newline the server sees.
        assertTrue(blocks("~u cmd=rm\\s+-rf", "https://e.test/?cmd=rm%09-rf"));
        assertTrue(blocks("~u cmd=rm\\s+-rf", "https://e.test/?cmd=rm%0A-rf"));
        assertTrue(blocks("~u cmd=rm[^&]-rf", "https://e.test/?cmd=rm%0D-rf"));
        // Raw controls still cannot end the URL early for an anchor.
        assertFalse(blocks("~u ^https://e\\.test/\\?n=a$", "https://e.test/?n=a%0Ab"));
    }

    @Test
    void anEscapedDelimiterInsideAValueStillHitsARestOfValueRule() {
        assertTrue(blocks("~u [?&]file=/files/[^&]*\\.exe", "https://e.test/?file=%2Ffiles%2Fa%26b.exe"));
        assertTrue(blocks("~u [?&]next=https?://[^&]*evil\\.example", "https://e.test/?next=https:%2F%2Fu%26x@evil.example"));
    }

    @Test
    void rawNonAsciiBytesLookLikeTheirEscapes() {
        // Request-line bytes arrive as ISO-8859-1 chars: raw UTF-8 é is \u00C3\u00A9.
        assertTrue(matches("~u /caf%C3%A9/", at("https://e.test/caf\u00C3\u00A9/")));
        assertTrue(blocks("~u q=caf\u00E9", "https://e.test/?q=caf\u00C3\u00A9"));
        assertEquals("https://e.test/a%A0%FFb", FlowFilter.normalizedUrl("https://e.test/a\u00A0\u00FFb"));
        assertEquals("https://m%C3%BCnchen.example/", FlowFilter.normalizedUrl("https://M\u00C3\u00BCnchen.example/"),
                "only ASCII letters are lower-cased: raw bytes keep their value");
    }

    @Test
    void theDecodedViewIsOnlyForFiltersWithAUrlRule() {
        assertTrue(FlowFilter.parse("~u x").usesUrl());
        assertTrue(FlowFilter.parse("x").usesUrl());
        assertTrue(FlowFilter.parse("~m GET & !(~u x | ~d y)").usesUrl());
        assertFalse(FlowFilter.parse("~bq secret").usesUrl());
        assertFalse(FlowFilter.parse("~d example\\.com & ~m POST").usesUrl());
    }

    /** As {@link BlockList} applies a rule: it blocks when it matches either URL form. */
    private static boolean blocks(String rule, String url) {
        FlowFilter filter = FlowFilter.parse(rule);
        FlowFilter.Flow flow = at(url);
        return filter.matches(flow) || FlowFilter.queryDecoded(flow).stream().anyMatch(filter::matches);
    }

    @Test
    void sharedUrlFilterCasesWithTheBrowserAddOn() {
        // starlarky-addons urlFiltersMatchTheCanonicalUrlNotItsSpelling: deny rules.
        String bundle = "~u fabulous\\.bundle\\.js";
        String chat = "~u ^https://checkout\\.example\\.test/chat\\.js$";
        for (String url : new String[] {"https://shop.example/files/fabulous.bundle.js",
                "https://shop.example/files/%66abulous.bundle.js", "https://shop.example/files/fabulous%2Ebundle.js"}) {
            assertTrue(blocks(bundle, url), url);
        }
        for (String url : new String[] {"https://checkout.example.test:443/chat.js", "https://CHECKOUT.example.test/chat.js",
                "https://checkout.example.test/%63hat.js"}) {
            assertTrue(blocks(chat, url), url);
        }
        assertFalse(blocks(chat, "https://checkout.example.test:8443/chat.js"));
        assertFalse(blocks(bundle, "https://shop.example/files/app.bundle.js"));
        String file = "~u [?&]file=/files/fabulous\\.bundle\\.js";
        assertTrue(blocks(file, "https://shop.example/dl?file=/files/fabulous.bundle.js"));
        assertTrue(blocks(file, "https://shop.example/dl?file=%2Ffiles%2Ffabulous.bundle.js"));
        assertFalse(blocks(file, "https://shop.example/dl?file=%2Ffiles%2Fapp.bundle.js"));
        // Allow-only, written for BlockList as "block what is not allowed".
        String allow = "!(~u ^https://checkout\\.example\\.test/pay$ | ~u ^https://checkout\\.example\\.test/dl\\?file=/ok$)";
        assertTrue(blocks(allow, "https://checkout.example.test/dl?file=%2Fok"), "decoding does not widen an allow");
        assertFalse(blocks(allow, "https://checkout.example.test:443/%70ay"));
        assertTrue(blocks(allow, "https://checkout.example.test/pay?next=1"));
    }

    @Test
    void anAllowRuleSeesTheNormalizedUrlAsWell() {
        // !~u /public/ blocks everything else; an escaped /public/ is still /public/.
        assertFalse(matches("!~u /public/", at("http://example.com/%70ublic/x")));
        assertTrue(matches("!~u /public/", at("http://example.com/other/x")));
    }

    @Test
    void normalizedUrl() {
        assertEquals("https://example.com/ads/?q=%26#f", FlowFilter.normalizedUrl("HTTPS://EXAMPLE.com:443/%61ds/?q=%26#f"));
        assertEquals("http://example.com", FlowFilter.normalizedUrl("http://Example.com:80"));
        assertEquals("http://example.com:8080/", FlowFilter.normalizedUrl("http://example.com:8080/"));
        assertEquals("http://example.com/%C3%A9%2F", FlowFilter.normalizedUrl("http://example.com/%c3%a9%2f"),
                "other escapes stay escaped, in upper-case hex");
        assertEquals("http://example.com/%%D9%A3%D9%A3", FlowFilter.normalizedUrl("http://example.com/%\u0663\u0663"),
                "only ASCII hex digits make an escape; the non-ASCII digits are escaped as UTF-8");
        assertEquals("example.com/x", FlowFilter.normalizedUrl("example.com/x"), "not absolute: only escapes change");
        assertEquals("http://example.com/%2561", FlowFilter.normalizedUrl("http://example.com/%2561"), "decoded once only");
        assertEquals("http://example.com/%6", FlowFilter.normalizedUrl("http://example.com/%6"));
        assertEquals("http://[::1]/", FlowFilter.normalizedUrl("http://[::1]/"));
        assertEquals("http://[::1]:8080/", FlowFilter.normalizedUrl("http://[::1]:08080/"));
        assertEquals("http://[fe80::1%25en0]/", FlowFilter.normalizedUrl("http://[fe80::1%25en0]:80/"));
        assertEquals("http://[fe80::1%31]/", FlowFilter.normalizedUrl("http://[fe80::1%31]/"), "zone ids are not decoded");
        // As URI.toASCIIString() hands them over: non-ASCII stays escaped, IDN hosts are punycode.
        assertEquals("https://xn--mnchen-3ya.example/stra%C3%9Fe/%C3%BC?q=%C3%BC",
                FlowFilter.normalizedUrl("https://XN--MNCHEN-3YA.example/stra%c3%9fe/%c3%bc?q=%c3%bc"));
        assertEquals("foo://h:-1/", FlowFilter.normalizedUrl("foo://h:-1/"), "no default port for an unknown scheme");
        assertEquals("http://", FlowFilter.normalizedUrl("http://"));
        assertEquals("a:b://x", FlowFilter.normalizedUrl("a:b://x"));
        assertEquals("http://example.com:99999/", FlowFilter.normalizedUrl("http://example.com:99999/"), "not a port: kept");
        assertEquals("http://example.com/a/g", FlowFilter.normalizedUrl("http://example.com/a/b/c/./../../g"));
        assertEquals("http://example.com/", FlowFilter.normalizedUrl("http://example.com/../../"));
        assertEquals("http://example.com/a/", FlowFilter.normalizedUrl("http://example.com/a/b/.."));
        assertEquals("http://example.com//admin", FlowFilter.normalizedUrl("http://example.com//admin"), "empty segments stay");
        assertEquals("http://example.com/x/admin", FlowFilter.normalizedUrl("http://example.com/x//../admin"),
                "RFC 3986: .. removes the empty segment (an origin that merges slashes first serves /admin)");
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
