package org.microproxy.extras;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.microproxy.HttpFilters;
import org.microproxy.http.DefaultHttpRequest;
import org.microproxy.http.DefaultHttpResponse;
import org.microproxy.http.HttpMethod;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpVersion;

/** Addons buffer a body only when a rule might select the exchange, judging from the heads. */
class AddonBufferingTest {

    private static HttpRequest request(HttpMethod method, String host, int bodyLength) {
        HttpRequest r = new DefaultHttpRequest(HttpVersion.HTTP_1_1, method, "http://" + host + "/p");
        r.headers().set("Host", host);
        if (bodyLength > 0) r.headers().set("Content-Length", String.valueOf(bodyLength));
        return r;
    }

    private static HttpResponse response(String type, String encoding) {
        HttpResponse r = new DefaultHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK);
        r.headers().set("Content-Type", type);
        r.headers().set("Content-Length", "100");
        if (encoding != null) r.headers().set("Content-Encoding", encoding);
        return r;
    }

    private static HttpFilters filters(ModifyBody addon, HttpRequest request) {
        HttpFilters f = addon.filterRequest(request, null);
        f.requestBufferSizeInBytes(request);
        f.clientToProxyRequest(request);
        return f;
    }

    @Test
    void modifyBodyBuffersOnlyResponsesItMightEdit() {
        ModifyBody addon = ModifyBody.builder().add("|~d example\\.com & ~t html & ~bs x|a|b").maxBodySize(1234).build();
        assertEquals(1234, filters(addon, request(HttpMethod.GET, "example.com", 0))
                .responseBufferSizeInBytes(response("text/html", "gzip")));
        assertEquals(0, filters(addon, request(HttpMethod.GET, "example.org", 0))
                .responseBufferSizeInBytes(response("text/html", null)), "another host");
        assertEquals(0, filters(addon, request(HttpMethod.GET, "example.com", 0))
                .responseBufferSizeInBytes(response("image/png", null)), "another type");
        assertEquals(0, filters(addon, request(HttpMethod.GET, "example.com", 0))
                .responseBufferSizeInBytes(response("text/html", "dcb")), "an undecodable coding");
        assertEquals(0, filters(addon, request(HttpMethod.GET, "example.com", 0))
                .responseBufferSizeInBytes(response("text/event-stream", null)), "an event stream");
    }

    @Test
    void modifyBodyBuffersRequestsOnlyForRequestRules() {
        ModifyBody responsesOnly = ModifyBody.of("|~s|a|b");
        HttpRequest post = request(HttpMethod.POST, "example.com", 10);
        assertEquals(0, responsesOnly.filterRequest(post, null).requestBufferSizeInBytes(post));
        ModifyBody requests = ModifyBody.of("|~q & ~m POST|a|b");
        assertTrue(requests.filterRequest(post, null).requestBufferSizeInBytes(post) > 0);
        HttpRequest get = request(HttpMethod.GET, "example.com", 0);
        assertEquals(0, requests.filterRequest(get, null).requestBufferSizeInBytes(get), "no body to edit");
    }

    @Test
    void headOnlyRulesNeverBufferRequests() {
        HttpRequest post = request(HttpMethod.POST, "example.com", 10);
        assertEquals(0, MapRemote.of("|~m POST|a|b").filterRequest(post, null).requestBufferSizeInBytes(post));
        assertEquals(0, BlockList.of("|~m POST|404").filterRequest(post, null).requestBufferSizeInBytes(post));
        assertTrue(BlockList.of("|~m POST & ~bq secret|404").filterRequest(post, null).requestBufferSizeInBytes(post) > 0);
        assertEquals(0, BlockList.of("|~m GET & ~bq secret|404").filterRequest(post, null).requestBufferSizeInBytes(post),
                "the head already rules it out");
    }
}
