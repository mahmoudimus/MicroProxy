package org.microproxy;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;
import org.microproxy.http.WebSocketFrame;

/**
 * Runs several filters sources as one, in order. For each request every source may contribute
 * filters, and they form a pipeline:
 *
 * <ul>
 *   <li>Request hooks run first to last; the first short-circuit response wins and later filters
 *       do not see the request. {@code proxyToServerFailure} works the same way: the first
 *       response wins.
 *   <li>Response hooks ({@code serverToProxyResponse}, {@code proxyToClientResponse}) and {@code
 *       filterWebSocketFrame} also run first to last, each receiving the previous one's result;
 *       {@code null} aborts (or drops the frame).
 *   <li>Buffer sizes are the largest any filter asks for.
 *   <li>Interception needs every filter's consent ({@code proxyToServerAllowMitm}), while {@code
 *       proxyToServerAllowOfflineMitm} needs any one filter's.
 *   <li>Notifications go to every filter.
 * </ul>
 *
 * <p>So a cache placed last stores responses after earlier filters have rewritten them, and
 * earlier filters see requests before the cache can answer them.
 */
public final class HttpFiltersChain implements HttpFiltersSource {

    private final List<HttpFiltersSource> sources;

    private HttpFiltersChain(List<HttpFiltersSource> sources) {
        this.sources = sources;
    }

    /** Chains {@code sources}, flattening nested chains. */
    public static HttpFiltersSource of(HttpFiltersSource... sources) {
        List<HttpFiltersSource> flat = new ArrayList<>();
        for (HttpFiltersSource source : sources) {
            if (source instanceof HttpFiltersChain chain) {
                flat.addAll(chain.sources);
            } else if (source != null && source.getClass() != HttpFiltersSourceAdapter.class) {
                flat.add(source);
            }
        }
        if (flat.isEmpty()) return new HttpFiltersSourceAdapter();
        if (flat.size() == 1) return flat.getFirst();
        return new HttpFiltersChain(List.copyOf(flat));
    }

    /** The chained sources, in order. */
    public List<HttpFiltersSource> sources() {
        return sources;
    }

    @Override
    public HttpFilters filterRequest(HttpRequest originalRequest, FlowContext flowContext) {
        List<HttpFilters> filters = new ArrayList<>(sources.size());
        for (HttpFiltersSource source : sources) {
            HttpFilters f = source.filterRequest(originalRequest, flowContext);
            if (f != null) filters.add(f);
        }
        return switch (filters.size()) {
            case 0 -> null;
            case 1 -> filters.getFirst();
            default -> new Chained(List.copyOf(filters));
        };
    }

    @Override
    public int getMaximumRequestBufferSizeInBytes() {
        return sources.stream().mapToInt(HttpFiltersSource::getMaximumRequestBufferSizeInBytes).max().orElse(0);
    }

    @Override
    public int getMaximumResponseBufferSizeInBytes() {
        return sources.stream().mapToInt(HttpFiltersSource::getMaximumResponseBufferSizeInBytes).max().orElse(0);
    }

    /** The filters of several sources for one request. */
    public static final class Chained implements HttpFilters {
        private final List<HttpFilters> members;

        Chained(List<HttpFilters> members) {
            this.members = members;
        }

        /** The member filters, in order. */
        public List<HttpFilters> members() {
            return members;
        }

        @Override
        public int requestBufferSizeInBytes(HttpRequest request) {
            int max = 0;
            for (HttpFilters f : members) max = Math.max(max, f.requestBufferSizeInBytes(request));
            return max;
        }

        @Override
        public HttpResponse clientToProxyRequest(HttpObject httpObject) {
            for (HttpFilters f : members) {
                HttpResponse r = f.clientToProxyRequest(httpObject);
                if (r != null) return r;
            }
            return null;
        }

        @Override
        public HttpResponse proxyToServerRequest(HttpObject httpObject) {
            for (HttpFilters f : members) {
                HttpResponse r = f.proxyToServerRequest(httpObject);
                if (r != null) return r;
            }
            return null;
        }

        @Override
        public void proxyToServerRequestSending() {
            members.forEach(HttpFilters::proxyToServerRequestSending);
        }

        @Override
        public void proxyToServerRequestSent() {
            members.forEach(HttpFilters::proxyToServerRequestSent);
        }

        @Override
        public HttpObject serverToProxyResponse(HttpObject httpObject) {
            HttpObject o = httpObject;
            for (HttpFilters f : members) {
                o = f.serverToProxyResponse(o);
                if (o == null) return null;
            }
            return o;
        }

        @Override
        public int responseBufferSizeInBytes(HttpResponse response) {
            int max = 0;
            for (HttpFilters f : members) max = Math.max(max, f.responseBufferSizeInBytes(response));
            return max;
        }

        @Override
        public void serverToProxyResponseTimedOut() {
            members.forEach(HttpFilters::serverToProxyResponseTimedOut);
        }

        @Override
        public HttpResponse proxyToServerFailure(ProxyFailure failure) {
            for (HttpFilters f : members) {
                HttpResponse r = f.proxyToServerFailure(failure);
                if (r != null) return r;
            }
            return null;
        }

        @Override
        public void serverToProxyResponseReceiving() {
            members.forEach(HttpFilters::serverToProxyResponseReceiving);
        }

        @Override
        public void serverToProxyResponseReceived() {
            members.forEach(HttpFilters::serverToProxyResponseReceived);
        }

        @Override
        public HttpObject proxyToClientResponse(HttpObject httpObject) {
            HttpObject o = httpObject;
            for (HttpFilters f : members) {
                o = f.proxyToClientResponse(o);
                if (o == null) return null;
            }
            return o;
        }

        @Override
        public void proxyToClientResponseSent(HttpResponse response, ResponseSource source) {
            members.forEach(f -> f.proxyToClientResponseSent(response, source));
        }

        @Override
        public InetSocketAddress proxyToServerResolutionStarted(String hostAndPort) {
            InetSocketAddress resolved = null;
            for (HttpFilters f : members) {
                InetSocketAddress a = f.proxyToServerResolutionStarted(hostAndPort);
                if (resolved == null) resolved = a;
            }
            return resolved;
        }

        @Override
        public void proxyToServerResolutionFailed(String hostAndPort) {
            members.forEach(f -> f.proxyToServerResolutionFailed(hostAndPort));
        }

        @Override
        public void proxyToServerResolutionSucceeded(String serverHostAndPort, InetSocketAddress resolvedRemoteAddress) {
            members.forEach(f -> f.proxyToServerResolutionSucceeded(serverHostAndPort, resolvedRemoteAddress));
        }

        @Override
        public void proxyToServerConnectionStarted() {
            members.forEach(HttpFilters::proxyToServerConnectionStarted);
        }

        @Override
        public void proxyToServerConnectionSSLHandshakeStarted() {
            members.forEach(HttpFilters::proxyToServerConnectionSSLHandshakeStarted);
        }

        @Override
        public void proxyToServerConnectionFailed() {
            members.forEach(HttpFilters::proxyToServerConnectionFailed);
        }

        @Override
        public void proxyToServerConnectionSucceeded(FullFlowContext serverContext) {
            members.forEach(f -> f.proxyToServerConnectionSucceeded(serverContext));
        }

        @Override
        public boolean proxyToServerAllowMitm() {
            for (HttpFilters f : members) {
                if (!f.proxyToServerAllowMitm()) return false;
            }
            return true;
        }

        @Override
        public boolean proxyToServerAllowOfflineMitm() {
            for (HttpFilters f : members) {
                if (f.proxyToServerAllowOfflineMitm()) return true;
            }
            return false;
        }

        @Override
        public void webSocketFrameReceived(WebSocketFrame frame, boolean fromClient) {
            members.forEach(f -> f.webSocketFrameReceived(frame, fromClient));
        }

        @Override
        public void webSocketFrameReceived(Supplier<byte[]> frameBytes, boolean fromClient) {
            members.forEach(f -> f.webSocketFrameReceived(frameBytes, fromClient));
        }

        @Override
        public WebSocketFrame filterWebSocketFrame(WebSocketFrame frame, boolean fromClient) {
            WebSocketFrame f = frame;
            for (HttpFilters member : members) {
                f = member.filterWebSocketFrame(f, fromClient);
                if (f == null) return null;
            }
            return f;
        }
    }
}
