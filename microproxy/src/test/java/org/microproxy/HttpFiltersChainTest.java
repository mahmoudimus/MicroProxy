package org.microproxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.microproxy.http.DefaultFullHttpResponse;
import org.microproxy.http.DefaultHttpRequest;
import org.microproxy.http.HttpMethod;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpVersion;

class HttpFiltersChainTest {

    private final List<String> calls = new ArrayList<>();

    private HttpFiltersSource source(String name, boolean shortCircuit, int buffer, boolean allowMitm) {
        return new HttpFiltersSourceAdapter() {
            @Override
            public HttpFilters filterRequest(HttpRequest originalRequest, FlowContext ctx) {
                return new HttpFilters() {
                    @Override
                    public HttpResponse clientToProxyRequest(HttpObject o) {
                        calls.add(name + ".request");
                        return shortCircuit ? new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK) : null;
                    }

                    @Override
                    public HttpObject serverToProxyResponse(HttpObject o) {
                        calls.add(name + ".response");
                        ((HttpResponse) o).headers().add("X-Chain", name);
                        return o;
                    }

                    @Override
                    public int responseBufferSizeInBytes(HttpResponse response) {
                        return buffer;
                    }

                    @Override
                    public boolean proxyToServerAllowMitm() {
                        return allowMitm;
                    }
                };
            }

            @Override
            public int getMaximumResponseBufferSizeInBytes() {
                return buffer / 2;
            }
        };
    }

    private static final HttpRequest REQUEST = new DefaultHttpRequest(HttpVersion.HTTP_1_1, HttpMethod.GET, "/");

    @Test
    void filtersRunAsAPipeline() {
        HttpFiltersSource chain = HttpFiltersChain.of(source("a", false, 10, true), source("b", false, 30, true));
        HttpFilters f = chain.filterRequest(REQUEST, null);
        assertNull(f.clientToProxyRequest(REQUEST));
        HttpResponse response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK);
        f.serverToProxyResponse(response);
        assertEquals(List.of("a.request", "b.request", "a.response", "b.response"), calls);
        assertEquals(List.of("a", "b"), response.headers().getAll("X-Chain"));
        assertEquals(30, f.responseBufferSizeInBytes(response));
        assertEquals(15, chain.getMaximumResponseBufferSizeInBytes());
        assertTrue(f.proxyToServerAllowMitm());
        assertFalse(f.proxyToServerAllowOfflineMitm());
    }

    @Test
    void firstShortCircuitWinsAndAnyFilterCanRefuseMitm() {
        HttpFilters f = HttpFiltersChain.of(source("a", true, 0, true), source("b", true, 0, false))
                .filterRequest(REQUEST, null);
        HttpResponse r = f.clientToProxyRequest(REQUEST);
        assertEquals(200, r.status().code());
        assertEquals(List.of("a.request"), calls);
        assertFalse(f.proxyToServerAllowMitm());
    }

    @Test
    void trivialChainsCollapse() {
        HttpFiltersSource a = source("a", false, 0, true);
        assertSame(a, HttpFiltersChain.of(new HttpFiltersSourceAdapter(), a, null));
        HttpFiltersSource nested = HttpFiltersChain.of(HttpFiltersChain.of(a, source("b", false, 0, true)), source("c", false, 0, true));
        assertEquals(3, ((HttpFiltersChain) nested).sources().size());
    }
}
