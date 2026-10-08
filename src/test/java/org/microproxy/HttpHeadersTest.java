package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.microproxy.http.DefaultHttpRequest;
import org.microproxy.http.HttpHeaders;
import org.microproxy.http.HttpMethod;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpUtil;
import org.microproxy.http.HttpVersion;

class HttpHeadersTest {

    @Test
    void caseInsensitiveMultimap() {
        HttpHeaders h = new HttpHeaders().add("Accept", "a").add("X-Y", "1").add("accept", "b");
        assertEquals("a", h.get("ACCEPT"));
        assertEquals(List.of("a", "b"), h.getAll("Accept"));
        h.set("ACCEPT", "c");
        assertEquals(List.of("c"), h.getAll("accept"));
        assertEquals("Accept: c\r\nX-Y: 1\r\n", h.toString(), "set keeps the first position");
        assertTrue(h.remove("x-y"));
        assertFalse(h.contains("X-Y"));
    }

    @Test
    void rejectsHeaderInjection() {
        HttpHeaders h = new HttpHeaders();
        assertThrows(IllegalArgumentException.class, () -> h.add("X", "a\r\nInjected: yes"));
        assertThrows(IllegalArgumentException.class, () -> h.add("Bad Name", "v"));
        assertThrows(IllegalArgumentException.class,
                () -> new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "/a b"));
    }

    @Test
    void keepAliveAndChunkedHelpers() {
        DefaultHttpRequest r10 = new DefaultHttpRequest(HttpVersion.HTTP_1_0, HttpMethod.GET, "/");
        assertFalse(HttpUtil.isKeepAlive(r10));
        HttpUtil.setKeepAlive(r10, true);
        assertEquals("keep-alive", r10.headers().get("Connection"));
        DefaultHttpRequest r11 = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "/");
        r11.headers().set("Connection", "Upgrade, close");
        assertFalse(HttpUtil.isKeepAlive(r11));

        r11.headers().set("Transfer-Encoding", "gzip");
        r11.headers().set("Content-Length", "5");
        HttpUtil.setTransferEncodingChunked(r11, true);
        assertEquals("gzip, chunked", r11.headers().get("Transfer-Encoding"));
        assertFalse(r11.headers().contains("Content-Length"));
        HttpUtil.setTransferEncodingChunked(r11, false);
        assertEquals("gzip", r11.headers().get("Transfer-Encoding"));
    }

    @Test
    void statusAndMethodValueSemantics() {
        assertEquals(HttpResponseStatus.OK, HttpResponseStatus.valueOf(200, "Fine"));
        assertTrue(HttpMethod.GET == HttpMethod.valueOf("GET"));
        assertEquals("PROPFIND", HttpMethod.valueOf("PROPFIND").name());
        assertEquals(HttpVersion.HTTP_1_1, HttpVersion.valueOf("HTTP/1.1"));
    }
}
