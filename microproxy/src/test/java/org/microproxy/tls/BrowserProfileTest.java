package org.microproxy.tls;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.microproxy.http.HttpHeaders;

class BrowserProfileTest {

    private static HttpHeaders clientHeaders() {
        HttpHeaders h = new HttpHeaders();
        h.add("Host", "example.com");
        h.add("User-Agent", "Java-http-client/21");
        h.add("X-Request-Id", "42");
        h.add("Via", "1.1 proxy.local");
        h.add("Accept", "application/json");
        return h;
    }

    @Test
    void theBrowsersHeadersComeFirstInItsOrderAndTheClientsAfter() {
        HttpHeaders h = clientHeaders();
        BrowserProfile.chrome156().applyHeaders(h, true);
        List<String> names = h.entries().stream().map(Map.Entry::getKey).toList();
        assertEquals(List.of("sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "upgrade-insecure-requests", "user-agent",
                "Accept", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-user", "sec-fetch-dest", "accept-language", "priority",
                "Host", "X-Request-Id"), names);
        assertTrue(h.get("user-agent").contains("Chrome/156.0.0.0") && !h.get("user-agent").contains("Headless"));
        // the client's own Accept is kept
        assertEquals("application/json", h.get("accept"));
    }

    @Test
    void viaIsRemovedAndAcceptEncodingNotAdded() {
        HttpHeaders h = clientHeaders();
        BrowserProfile.chrome156().applyHeaders(h, true);
        assertNull(h.get("via"));
        assertNull(h.get("accept-encoding"), "a client that asked for no encoding must get none");
    }

    @Test
    void theClientsUserAgentStaysUnlessReplaced() {
        HttpHeaders h = clientHeaders();
        BrowserProfile.chrome156().applyHeaders(h, false);
        assertEquals("Java-http-client/21", h.get("user-agent"));
        HttpHeaders none = new HttpHeaders();
        BrowserProfile.chrome156().applyHeaders(none, false);
        assertTrue(none.get("user-agent").startsWith("Mozilla/5.0"));
    }

    @Test
    void aClientsAcceptEncodingIsKept() {
        HttpHeaders h = new HttpHeaders();
        h.add("accept-encoding", "gzip");
        BrowserProfile.chrome156().applyHeaders(h, true);
        assertEquals("gzip", h.get("accept-encoding"));
        assertFalse(h.getAll("accept-encoding").size() > 1);
    }

    @Test
    void certificatesDecompressWithBrotliAndZlib() throws Exception {
        byte[] chain = new byte[3000];
        for (int i = 0; i < chain.length; i++) chain[i] = (byte) (i % 13);
        byte[] brotli = org.microproxy.thirdparty.jaybrotli.Brotli.compress(chain);
        assertEquals(chain.length,
                BrowserProfile.certificateDecompressor().decompress(io.github.mahmoudimus.quic.tls.ProfileExtensions.BROTLI, brotli, 3000).length);
    }
}
