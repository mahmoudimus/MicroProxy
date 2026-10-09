package org.microproxy.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.microproxy.http.HttpHeaders;

/** Removing HTTP/3 alternatives from {@code Alt-Svc} field values. */
class AltSvcTest {

    @Test
    void removesH3AndKeepsTheOthersWithTheirParameters() {
        assertEquals("h2=\":443\"; ma=2592000", AltSvc.stripHttp3("h3=\":443\"; ma=2592000, h2=\":443\"; ma=2592000"));
        assertEquals("h2=\"alt.example.com:443\"; ma=60; persist=1",
                AltSvc.stripHttp3("h2=\"alt.example.com:443\"; ma=60; persist=1,h3=\":443\""));
    }

    @Test
    void removesDraftAndGoogleQuicVersions() {
        String value = "h3-29=\":443\"; ma=86400, h3-Q050=\":443\"; ma=86400, h3-T051=\":443\","
                + " quic=\":443\"; ma=2592000; v=\"46,43\", h2=\":443\"";
        assertEquals("h2=\":443\"", AltSvc.stripHttp3(value));
        assertEquals("h2=\":443\"", AltSvc.stripHttp3("H3=\":443\", h2=\":443\""), "ALPN ids compared case-insensitively");
        assertEquals("h2=\":443\"", AltSvc.stripHttp3("%68%33=\":443\", h2=\":443\""), "percent-encoded id");
    }

    @Test
    void protocolsThatOnlyStartLikeH3AreKept() {
        String value = "h3x=\":443\", h2c=\":80\", h31=\":443\"";
        assertSame(value, AltSvc.stripHttp3(value));
    }

    @Test
    void commasAndSemicolonsInsideQuotedStringsDoNotSplit() {
        // Quoted parameter values may hold commas; an escaped quote does not end the string.
        String value = "h2=\":443\"; note=\"a, h3=\\\":443\\\"; b\", h3=\":8443\"; ma=10";
        assertEquals("h2=\":443\"; note=\"a, h3=\\\":443\\\"; b\"", AltSvc.stripHttp3(value));
        assertEquals(List.of("h2=\"x,y:443\"", "h3=\":443\""), AltSvc.split(" h2=\"x,y:443\" ,h3=\":443\" "));
    }

    @Test
    void unterminatedQuotesRunToTheEnd() {
        assertEquals(List.of("h2=\":443, h3=\":443\""), AltSvc.split("h2=\":443, h3=\":443\""));
        assertNull(AltSvc.stripHttp3("h3=\":443, h2=\":443\""), "one (malformed) h3 alternative");
    }

    @Test
    void nothingLeftMeansNoValue() {
        assertNull(AltSvc.stripHttp3("h3=\":443\"; ma=86400"));
        assertNull(AltSvc.stripHttp3("h3=\":443\", h3-29=\":443\""));
        assertNull(AltSvc.stripHttp3("h3=\":443\", , "), "empty list elements are dropped too");
    }

    @Test
    void valuesWithoutH3AreLeftExactlyAsReceived() {
        String clear = "clear";
        assertSame(clear, AltSvc.stripHttp3(clear));
        String spaced = " clear ";
        assertSame(spaced, AltSvc.stripHttp3(spaced));
        String odd = "h2=\":443\" ,, h2=\"b:443\";ma=5";
        assertSame(odd, AltSvc.stripHttp3(odd), "no rewrite, so the odd spacing and empty element stay");
        assertSame("", AltSvc.stripHttp3(""));
    }

    @Test
    void stripsEveryFieldAndCombinesWhatRemains() {
        HttpHeaders headers = new HttpHeaders()
                .add("Content-Type", "text/plain")
                .add("alt-svc", "h3=\":443\"; ma=86400")
                .add("X-Other", "1")
                .add("Alt-Svc", "h2=\":443\"; ma=86400, h3-29=\":443\"")
                .add("ALT-SVC", "h2=\"b.example:443\"; persist=1");
        assertTrue(AltSvc.stripHttp3(headers));
        assertEquals(List.of("h2=\":443\"; ma=86400, h2=\"b.example:443\"; persist=1"), headers.getAll("Alt-Svc"));
        assertEquals("alt-svc", headers.nameAt(1), "in place of the first field");
        assertEquals("X-Other", headers.nameAt(2));
    }

    @Test
    void removesTheHeaderWhenNothingRemains() {
        HttpHeaders headers = new HttpHeaders().add("Alt-Svc", "h3=\":443\"").add("Alt-Svc", "h3-29=\":443\"; ma=1");
        assertTrue(AltSvc.stripHttp3(headers));
        assertFalse(headers.contains("Alt-Svc"));
    }

    @Test
    void headersWithoutH3AreNotTouched() {
        HttpHeaders headers = new HttpHeaders().add("Alt-Svc", "h2=\":443\"").add("Alt-Svc", "clear");
        assertFalse(AltSvc.stripHttp3(headers));
        assertEquals(List.of("h2=\":443\"", "clear"), headers.getAll("Alt-Svc"));
        assertFalse(AltSvc.stripHttp3(new HttpHeaders()));
    }

    @Test
    void defaultsFollowInterceptionAndTransparency() {
        DefaultHttpProxyServerBootstrap plain = new DefaultHttpProxyServerBootstrap();
        assertFalse(plain.stripsAltSvcH3(), "a plain forward proxy leaves Alt-Svc alone");
        DefaultHttpProxyServerBootstrap transparent = new DefaultHttpProxyServerBootstrap();
        transparent.withTransparent(true);
        assertTrue(transparent.stripsAltSvcH3());
        DefaultHttpProxyServerBootstrap optedOut = new DefaultHttpProxyServerBootstrap();
        optedOut.withTransparent(true).withAltSvcH3Stripping(false);
        assertFalse(optedOut.stripsAltSvcH3());
        assertTrue(new DefaultHttpProxyServerBootstrap().withoutHttp3Advertisement() instanceof DefaultHttpProxyServerBootstrap b
                && b.stripsAltSvcH3());
        assertFalse(optedOut.copy().stripsAltSvcH3(), "copied");
    }
}
