package org.microproxy.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.microproxy.http.HttpHeaders;

/** The allocation-free helpers behave like the regular expressions they replaced. */
class ProxyUtilsTest {

    private static final Pattern ABSOLUTE = Pattern.compile("^[a-zA-Z][a-zA-Z0-9+.-]*://.*");
    private static final Pattern HTTP = Pattern.compile("^(http|ws)s?://.*", Pattern.CASE_INSENSITIVE);

    @Test
    void uriChecksMatchTheOldPatterns() {
        for (String uri : List.of("http://a/b", "HTTPS://a", "ws://x", "wss://x:1/", "ftp://x", "a+b.c-d://x", "1http://x",
                "http:/x", "/path", "", "h", "host:443", "x://", "mailto:me", "HTTP://", "http//x")) {
            assertEquals(ABSOLUTE.matcher(uri).matches(), ProxyUtils.isAbsoluteUri(uri), uri);
            boolean http = HTTP.matcher(uri).matches();
            assertEquals(http, ProxyUtils.parseHostAndPort(uri) != null, uri);
            if (!http) assertSame(uri, ProxyUtils.stripHost(uri));
        }
        assertEquals("h:8", ProxyUtils.parseHostAndPort("HTTP://u:p@h:8/x"));
        assertEquals("/x?y", ProxyUtils.stripHost("Http://h/x?y"));
        assertEquals("/?q", ProxyUtils.stripHost("http://h?q"));
    }

    @Test
    void hopByHopStrippingIsCaseInsensitive() {
        HttpHeaders h = new HttpHeaders();
        h.add("Keep-Alive", "timeout=5").add("X-Kept", "1").add("TE", "trailers").add("upgrade", "h2c");
        ProxyUtils.stripHopByHopHeaders(h);
        assertEquals(1, h.size());
        assertEquals("X-Kept", h.nameAt(0));
    }

    @Test
    void connectionTokensAndListElements() {
        HttpHeaders h = new HttpHeaders();
        h.add("Connection", " close , X-Private").add("X-Private", "secret").add("Transfer-Encoding", "chunked");
        assertTrue(h.containsValue("connection", "CLOSE", true));
        assertFalse(h.containsValue("connection", "CLOSE", false));
        assertFalse(h.containsValue("connection", "clos", true));
        ProxyUtils.stripConnectionTokens(h);
        assertFalse(h.contains("X-Private"));
        assertTrue(h.contains("Transfer-Encoding"));
        assertEquals(1, h.count("connection"));
    }

    @Test
    void sdchIsRemovedOnlyWhenPresent() {
        HttpHeaders h = new HttpHeaders();
        h.add("Accept-Encoding", "gzip,deflate");
        ProxyUtils.removeSdchEncoding(h);
        assertEquals("gzip,deflate", h.get("Accept-Encoding"));
        h.set("Accept-Encoding", "gzip, SDCH, br");
        ProxyUtils.removeSdchEncoding(h);
        assertEquals("gzip, br", h.get("Accept-Encoding"));
        HttpHeaders none = new HttpHeaders();
        ProxyUtils.removeSdchEncoding(none);
        assertNull(none.get("Accept-Encoding"));
    }

    @Test
    void httpDateIsCachedPerSecond() {
        String a = ProxyUtils.httpDate();
        assertTrue(a.matches("[A-Z][a-z]{2}, \\d{2} [A-Z][a-z]{2} \\d{4} \\d{2}:\\d{2}:\\d{2} GMT"), a);
        // Within one second the same string comes back.
        String b = ProxyUtils.httpDate();
        if (a.equals(b)) assertSame(a, b);
    }
}
