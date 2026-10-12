package org.microproxy.otel;

import java.net.InetSocketAddress;
import java.util.EnumSet;
import java.util.Locale;
import java.util.Set;
import org.microproxy.FlowContext;
import org.microproxy.FlowRecord;
import org.microproxy.FlowTimings;
import org.microproxy.ProxyFailure;
import org.microproxy.ResponseFlag;
import org.microproxy.http.HttpHeaderNames;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpVersion;

/**
 * OpenTelemetry's semantic conventions for HTTP, as the proxy's spans and log records carry them
 * ({@code http.request.method}, {@code url.full}, {@code server.address}, ...), plus Envoy's
 * tracing tags ({@code response_flags}, {@code upstream_cluster}, {@code guid:x-request-id}) and
 * the proxy's own ({@code microproxy.*}).
 */
final class Semconv {

    private Semconv() {}

    /** The methods {@code http.request.method} names; others are {@code _OTHER}. */
    private static final Set<String> KNOWN_METHODS =
            Set.of("CONNECT", "DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", "TRACE", "QUERY");

    /** The flags that mean the proxy or the server failed, rather than the client or a policy. */
    static final Set<ResponseFlag> ERROR_FLAGS = EnumSet.of(
            ResponseFlag.NO_HEALTHY_UPSTREAM, ResponseFlag.UPSTREAM_REQUEST_TIMEOUT, ResponseFlag.LOCAL_RESET,
            ResponseFlag.UPSTREAM_REMOTE_RESET, ResponseFlag.UPSTREAM_CONNECTION_FAILURE,
            ResponseFlag.UPSTREAM_CONNECTION_TERMINATION, ResponseFlag.UPSTREAM_OVERFLOW, ResponseFlag.NO_ROUTE_FOUND,
            ResponseFlag.UPSTREAM_RETRY_LIMIT_EXCEEDED, ResponseFlag.UPSTREAM_PROTOCOL_ERROR,
            ResponseFlag.DNS_RESOLUTION_FAILED);

    /**
     * What spans need of a request, read when it arrives (the request itself changes while it is
     * proxied).
     *
     * @param method the method
     * @param uri the request-target as the client sent it
     * @param host the {@code Host} header (the {@code :authority}), or {@code null}
     * @param userAgent the {@code User-Agent}, or {@code null}
     * @param version {@code 1.0}, {@code 1.1}, {@code 2} or {@code 3}
     * @param secure whether the client connection is TLS (QUIC included)
     * @param client the client's address, or {@code null}
     */
    record RequestInfo(String method, String uri, String host, String userAgent, String version, boolean secure,
            InetSocketAddress client) {

        static RequestInfo of(HttpRequest request, FlowContext flow) {
            HttpVersion v = flow.getStreamId() != 0 || flow.getHttpVersion().majorVersion() >= 2 ? flow.getHttpVersion()
                    : request.protocolVersion();
            String version = v.majorVersion() >= 2 ? Integer.toString(v.majorVersion())
                    : v.majorVersion() + "." + v.minorVersion();
            return new RequestInfo(request.method().name(), request.uri(), request.headers().get(HttpHeaderNames.HOST),
                    request.headers().get(HttpHeaderNames.USER_AGENT), version,
                    flow.getClientSslSession() != null || v.majorVersion() == 3, flow.getClientAddress());
        }

        boolean isConnect() {
            return "CONNECT".equals(method);
        }

        /** The scheme of an absolute-form target, else the client connection's. */
        String scheme() {
            int i = uri.indexOf("://");
            if (i > 0 && uri.charAt(0) != '/') return uri.substring(0, i).toLowerCase(Locale.ROOT);
            return secure ? "https" : "http";
        }

        boolean absolute() {
            int i = uri.indexOf("://");
            return i > 0 && uri.charAt(0) != '/';
        }

        /** The {@code host[:port]} the request names: the absolute target's, the CONNECT target, or the Host. */
        String authority() {
            if (isConnect()) return uri;
            if (absolute()) {
                int start = uri.indexOf("://") + 3;
                int end = start;
                while (end < uri.length() && "/?#".indexOf(uri.charAt(end)) < 0) end++;
                String authority = uri.substring(start, end);
                int at = authority.lastIndexOf('@');
                return at >= 0 ? authority.substring(at + 1) : authority;
            }
            return host;
        }

        /** The path and query of the target, or {@code null} for an authority-form one. */
        String pathAndQuery() {
            if (isConnect()) return null;
            if (absolute()) {
                int start = uri.indexOf("://") + 3;
                int slash = start;
                while (slash < uri.length() && "/?#".indexOf(uri.charAt(slash)) < 0) slash++;
                String rest = uri.substring(slash);
                return rest.isEmpty() ? "/" : rest;
            }
            return uri;
        }
    }

    /** {@code host} of {@code host[:port]} (brackets of an IPv6 literal removed), or {@code null}. */
    static String hostOf(String authority) {
        if (authority == null || authority.isEmpty()) return null;
        if (authority.startsWith("[")) {
            int close = authority.indexOf(']');
            return close > 0 ? authority.substring(1, close) : authority;
        }
        int colon = authority.lastIndexOf(':');
        return colon >= 0 && authority.indexOf(':') == colon ? authority.substring(0, colon) : authority;
    }

    /** The port of {@code host:port}, else {@code defaultPort}. */
    static long portOf(String authority, long defaultPort) {
        if (authority == null) return defaultPort;
        int colon = authority.lastIndexOf(':');
        int close = authority.lastIndexOf(']');
        if (colon < 0 || colon < close || !authority.startsWith("[") && authority.indexOf(':') != colon) return defaultPort;
        try {
            return Long.parseLong(authority.substring(colon + 1));
        } catch (NumberFormatException e) {
            return defaultPort;
        }
    }

    static long defaultPort(String scheme) {
        return switch (scheme) {
            case "https", "wss" -> 443;
            case "http", "ws" -> 80;
            default -> -1;
        };
    }

    /** {@code http.request.method}, {@code _OTHER} for a method the conventions do not name. */
    static String method(String method) {
        return KNOWN_METHODS.contains(method) ? method : "_OTHER";
    }

    /**
     * {@code url.full} of a request to {@code hostAndPort}, with the path and query of {@code info}:
     * {@code https} when the proxy speaks TLS to the server, {@code http} otherwise.
     */
    static String upstreamUrl(RequestInfo info, String hostAndPort, boolean tls) {
        if (info.isConnect()) return null;
        String path = info.pathAndQuery();
        return (tls ? "https://" : "http://") + hostAndPort + (path == null || path.equals("*") ? "/" : path);
    }

    /** The request attributes of a SERVER span (and of the access log's record). */
    static void request(Attrs a, RequestInfo info) {
        String method = method(info.method());
        a.put("http.request.method", method);
        if (method.equals("_OTHER")) a.put("http.request.method_original", info.method());
        String scheme = info.scheme();
        String authority = info.authority();
        if (!info.isConnect()) {
            a.put("url.scheme", scheme);
            String pq = info.pathAndQuery();
            if (pq != null) {
                int q = pq.indexOf('?');
                a.put("url.path", q >= 0 ? pq.substring(0, q) : pq);
                if (q >= 0 && q + 1 < pq.length()) a.put("url.query", pq.substring(q + 1));
            }
            if (info.absolute()) a.put("url.full", info.uri());
        }
        String host = hostOf(authority);
        if (host != null) {
            a.put("server.address", host);
            long port = portOf(authority, defaultPort(scheme));
            if (port > 0) a.put("server.port", port);
        }
        client(a, info.client());
        if (info.userAgent() != null) a.put("user_agent.original", info.userAgent());
        a.put("network.protocol.name", "http");
        a.put("network.protocol.version", info.version());
    }

    static void client(Attrs a, InetSocketAddress client) {
        if (client == null) return;
        a.put("client.address", client.getAddress() != null ? client.getAddress().getHostAddress() : client.getHostString());
        a.put("client.port", (long) client.getPort());
    }

    /** The outcome of an exchange or flow, from its record: status, sizes, flags, upstream. */
    static void outcome(Attrs a, FlowRecord r) {
        int status = r.responseCode();
        if (status > 0) a.put("http.response.status_code", (long) status);
        if (r.kind().isHttp()) {
            if (r.bytesReceived() >= 0) a.put("http.request.body.size", r.bytesReceived());
            if (r.bytesSent() >= 0) a.put("http.response.body.size", r.bytesSent());
        } else {
            a.put("network.transport", r.kind() == FlowRecord.Kind.UDP || r.kind() == FlowRecord.Kind.QUIC
                    || r.kind() == FlowRecord.Kind.QUIC_RELAY ? "udp" : "tcp");
            if (r.bytesReceived() >= 0) a.put("microproxy.bytes_received", r.bytesReceived());
            if (r.bytesSent() >= 0) a.put("microproxy.bytes_sent", r.bytesSent());
            if (r.upstreamBytesSent() >= 0) a.put("microproxy.upstream_bytes_sent", r.upstreamBytesSent());
            if (r.upstreamBytesReceived() >= 0) a.put("microproxy.upstream_bytes_received", r.upstreamBytesReceived());
        }
        String error = errorType(r);
        if (error != null) a.put("error.type", error);
        if (!r.responseFlags().isEmpty()) a.put("response_flags", ResponseFlag.render(r.responseFlags(), false));
        if (r.upstreamCluster() != null) a.put("upstream_cluster", r.upstreamCluster());
        if (r.upstreamProtocol() != null) a.put("microproxy.upstream_protocol", r.upstreamProtocol());
        if (r.upstreamAddress() != null) a.put("upstream_address", address(r.upstreamAddress()));
        if (r.source() != null) a.put("microproxy.response_source", r.source().name());
        if (r.responseCodeDetails() != null) a.put("microproxy.response_code_details", r.responseCodeDetails());
        a.put("microproxy.flow", r.kind().label());
        a.put("microproxy.connection_id", r.context().getConnectionId());
        if (r.context().getStreamId() != 0) a.put("microproxy.stream_id", (long) r.context().getStreamId());
        r.context().socksVersion().ifPresent(v -> a.put("microproxy.socks_version", (long) v));
    }

    static String address(InetSocketAddress address) {
        String host = address.getAddress() != null ? address.getAddress().getHostAddress() : address.getHostString();
        return (host.indexOf(':') >= 0 ? "[" + host + "]" : host) + ":" + address.getPort();
    }

    /**
     * {@code error.type} of an exchange or flow: the status for a 5xx (HTTP), the failure's kind
     * ({@code connect_failed}, ...), or the details of an exchange that got no response for a
     * reason of the proxy's or the server's.
     */
    static String errorType(FlowRecord r) {
        int status = r.responseCode();
        if (r.kind().isHttp() && status >= 500) return Integer.toString(status);
        if (r.failure().isPresent()) return failureKind(r.failure().get());
        if (isError(r)) {
            return r.responseCodeDetails() != null ? r.responseCodeDetails()
                    : ResponseFlag.render(r.responseFlags(), false);
        }
        return null;
    }

    /** Whether the span of {@code r} has status ERROR: a 5xx, a failure, or a flag of the proxy's or the server's failing. */
    static boolean isError(FlowRecord r) {
        if (r.kind().isHttp() && r.responseCode() >= 500) return true;
        if (r.failure().isPresent()) return true;
        for (ResponseFlag f : r.responseFlags()) {
            if (ERROR_FLAGS.contains(f)) return true;
        }
        return false;
    }

    /** {@code connect_failed} for {@link ProxyFailure.ConnectFailed}, and so on. */
    static String failureKind(ProxyFailure failure) {
        String name = failure.getClass().getSimpleName();
        StringBuilder sb = new StringBuilder(name.length() + 4);
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            if (Character.isUpperCase(c)) {
                if (i > 0) sb.append('_');
                sb.append(Character.toLowerCase(c));
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /** The name of the span of a tunnel or flow: its kind and its target. */
    static String flowName(FlowRecord.Kind kind, RequestInfo info) {
        String target = info == null ? null : info.authority();
        return target == null ? kind.label() : kind.label() + " " + target;
    }

    /** Adds the events of the exchange's phases, timed from {@code startNanos} (epoch). */
    static void timingEvents(SpanBuilder span, FlowTimings t, long startNanos) {
        phase(span, "dns_lookup", t.dnsStartNanos(), t.dnsEndNanos(), startNanos);
        phase(span, "connect", t.connectStartNanos(), t.connectEndNanos(), startNanos);
        phase(span, "tls_handshake", t.tlsStartNanos(), t.tlsEndNanos(), startNanos);
        if (t.requestSentNanos() >= 0) span.event(startNanos + t.requestSentNanos(), "request_sent", null, 0);
        if (t.firstResponseByteNanos() >= 0) {
            span.event(startNanos + t.firstResponseByteNanos(), "first_byte", null, 0);
        }
        if (t.clientTlsHandshakeNanos() >= 0) {
            span.event(startNanos, "downstream_tls_handshake", "microproxy.duration_ms", t.clientTlsHandshakeNanos());
        }
    }

    private static void phase(SpanBuilder span, String name, long start, long end, long base) {
        if (start < 0 || end < start) return;
        span.event(base + end, name, "microproxy.duration_ms", end - start);
    }

    /** What collects the events of a span being finished. */
    interface SpanBuilder {
        /** An event at {@code timeNanos}, with a duration attribute in milliseconds when {@code key} is not null. */
        void event(long timeNanos, String name, String key, long durationNanos);
    }
}
