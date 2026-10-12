package org.microproxy.extras;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.microproxy.http.DefaultHttpRequest;
import org.microproxy.http.DefaultHttpResponse;
import org.microproxy.http.HttpMethod;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpVersion;

/** The cookie jar's RFC 6265 rules: domain, path, expiry and Secure. */
class StickyCookieTest {

    private final AtomicReference<Instant> now = new AtomicReference<>(Instant.parse("2026-01-01T00:00:00Z"));
    private final Clock clock = new Clock() {
        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now.get();
        }
    };
    private final StickyCookie jar = StickyCookie.matching(FlowFilter.ALL, clock);

    private void set(String url, String... cookies) {
        HttpResponse r = new DefaultHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK);
        for (String c : cookies) r.headers().add("Set-Cookie", c);
        jar.remember(url, r);
    }

    private String cookiesFor(String url, String existing) {
        HttpRequest r = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, url);
        if (existing != null) r.headers().set("Cookie", existing);
        jar.addCookies(r, url);
        return r.headers().get("Cookie");
    }

    private String cookiesFor(String url) {
        return cookiesFor(url, null);
    }

    @Test
    void hostOnlyCookiesStayOnTheirHost() {
        set("https://www.example.com/", "a=1");
        assertEquals("a=1", cookiesFor("https://www.example.com/x"));
        assertNull(cookiesFor("https://sub.www.example.com/x"));
        assertNull(cookiesFor("https://example.com/x"));
    }

    @Test
    void domainCookiesCoverSubdomains() {
        set("https://www.example.com/", "d=1; Domain=.Example.com");
        assertEquals("d=1", cookiesFor("https://example.com/"));
        assertEquals("d=1", cookiesFor("https://api.example.com/"));
        assertNull(cookiesFor("https://example.org/"));
        assertNull(cookiesFor("https://notexample.com/"));
        // A domain that does not cover the server, or a top-level one, is refused.
        set("https://www.example.com/", "evil=1; Domain=other.com", "tld=1; Domain=com");
        assertNull(cookiesFor("https://other.com/"));
        assertEquals("d=1", cookiesFor("https://x.example.com/"));
    }

    @Test
    void pathsDefaultToTheRequestDirectoryAndMatchOnSegments() {
        set("http://h.test/app/login", "dflt=1");
        set("http://h.test/", "api=1; Path=/api", "root=1; Path=/");
        assertEquals("dflt=1; root=1", cookiesFor("http://h.test/app/page"));
        assertEquals("root=1", cookiesFor("http://h.test/application"));
        assertEquals("api=1; root=1", cookiesFor("http://h.test/api"));
        assertEquals("api=1; root=1", cookiesFor("http://h.test/api/v1?x=1"));
        assertEquals("root=1", cookiesFor("http://h.test/apix"));
    }

    @Test
    void expiryFromMaxAgeOrExpires() {
        set("http://h.test/", "short=1; Max-Age=60", "dated=1; Expires=Thu, 01 Jan 2026 00:10:00 GMT",
                "both=1; Max-Age=3600; Expires=Thu, 01 Jan 1970 00:00:00 GMT", "session=1");
        assertEquals("short=1; dated=1; both=1; session=1", cookiesFor("http://h.test/"));
        now.set(now.get().plus(2, ChronoUnit.MINUTES));
        assertEquals("dated=1; both=1; session=1", cookiesFor("http://h.test/"));
        now.set(now.get().plus(20, ChronoUnit.MINUTES));
        assertEquals("both=1; session=1", cookiesFor("http://h.test/"));
        // Setting a cookie to expire removes it.
        set("http://h.test/", "session=; Max-Age=0", "both=1; Expires=Sun, 06-Nov-94 08:49:37 GMT");
        assertNull(cookiesFor("http://h.test/"));
    }

    @Test
    void secureCookiesOnlyGoOverHttpsAndClientCookiesWin() {
        set("https://h.test/", "s=1; Secure", "p=jar");
        assertEquals("p=jar", cookiesFor("http://h.test/"));
        assertEquals("s=1; p=jar", cookiesFor("https://h.test/"));
        assertEquals("p=mine; s=1", cookiesFor("https://h.test/", "p=mine"));
        set("https://h.test/", "p=new");
        assertEquals("s=1; p=new", cookiesFor("https://h.test/"));
        assertEquals(1, jar.cookies().size());
    }

    @Test
    void cookieDatesAreParsedLeniently() {
        Instant expected = Instant.parse("1994-11-06T08:49:37Z");
        assertEquals(expected, Cookies.parseDate("Sun, 06 Nov 1994 08:49:37 GMT"));
        assertEquals(expected, Cookies.parseDate("Sunday, 06-Nov-94 08:49:37 GMT"));
        assertEquals(expected, Cookies.parseDate("Sun Nov  6 08:49:37 1994"));
        assertNull(Cookies.parseDate("not a date"));
        assertNull(Cookies.parseDate("Sun, 32 Nov 1994 08:49:37 GMT"));
    }
}
