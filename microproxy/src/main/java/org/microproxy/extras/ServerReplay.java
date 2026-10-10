/*
 * Ported from mitmproxy's mitmproxy/addons/serverplayback.py and Response.refresh in
 * mitmproxy/http.py (https://github.com/mitmproxy/mitmproxy), Copyright (c) 2013, Aldo Cortesi.
 * Licensed under the MIT License; see META-INF/LICENSE-mitmproxy.txt.
 */
package org.microproxy.extras;

import static java.nio.charset.StandardCharsets.ISO_8859_1;

import java.io.IOException;
import java.lang.System.Logger.Level;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.locks.ReentrantLock;
import org.microproxy.FlowContext;
import org.microproxy.HttpFilters;
import org.microproxy.HttpFiltersSource;
import org.microproxy.ResponseSource;
import org.microproxy.http.DefaultFullHttpResponse;
import org.microproxy.http.FullHttpRequest;
import org.microproxy.http.HttpMethod;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpUtil;
import org.microproxy.http.HttpVersion;

/**
 * Answers requests from recorded responses instead of contacting servers, as mitmproxy's {@code
 * server_replay}. Recordings come from HAR files ({@link HarRecorder}, browsers, mitmproxy) or
 * WARC files ({@link org.microproxy.warc.WarcRecorder}):
 *
 * <pre>{@code
 * ServerReplay replay = ServerReplay.builder()
 *         .load(Path.of("flows.har"))
 *         .ignoreParams("_", "cachebust")
 *         .extra(ServerReplay.Extra.status(404))   // unmatched requests get 404 instead of the server
 *         .build();
 * MicroProxy.bootstrap().withFiltersSource(replay).start();
 * }</pre>
 *
 * <p><b>Matching</b> follows mitmproxy's {@code _hash}: a request matches a recording with the same
 * scheme, method, path, body, host, port and query parameters (in order), each part left out with
 * an option: {@link Builder#ignoreContent}, {@link Builder#ignoreHost}, {@link Builder#ignorePort},
 * {@link Builder#ignoreParams}, {@link Builder#ignorePayloadParams} (for {@code
 * application/x-www-form-urlencoded} bodies); {@link Builder#useHeaders} adds request headers.
 * Requests with a body are buffered to compare it (unless the body is ignored).
 *
 * <p><b>Use.</b> Each recording answers once, in recorded order, so a sequence of identical
 * requests gets the recorded sequence of responses; with {@link Builder#reuse} every recording
 * keeps answering. Requests with no recording left are forwarded to the server, or, with {@link
 * Builder#extra}, killed (the connection closed) or answered with a status. Replayed responses
 * have their {@code Date}, {@code Expires}, {@code Last-Modified} and {@code Set-Cookie} expiry
 * shifted by the time since they were recorded ({@link Builder#refresh}, on by default), and reach
 * trackers and logs as {@link ResponseSource#REPLAY}.
 *
 * <p>All recordings are held in memory. Exchanges without a response, and responses cut short
 * when they were recorded, are not replayed.
 */
public final class ServerReplay implements HttpFiltersSource {

    private static final System.Logger LOG = System.getLogger(ServerReplay.class.getName());

    private final boolean ignoreContent;
    private final boolean ignoreHost;
    private final boolean ignorePort;
    private final Set<String> ignoreParams;
    private final Set<String> ignorePayloadParams;
    private final List<String> useHeaders;
    private final boolean reuse;
    private final Extra extra;
    private final boolean refresh;
    private final int maxBodySize;
    private final Clock clock;
    private final ReentrantLock lock = new ReentrantLock();
    private final Map<List<String>, Deque<RecordedExchange>> flows = new HashMap<>();

    private ServerReplay(Builder b) {
        this.ignoreContent = b.ignoreContent;
        this.ignoreHost = b.ignoreHost;
        this.ignorePort = b.ignorePort;
        this.ignoreParams = Set.copyOf(b.ignoreParams);
        this.ignorePayloadParams = Set.copyOf(b.ignorePayloadParams);
        this.useHeaders = List.copyOf(b.useHeaders);
        this.reuse = b.reuse;
        this.extra = b.extra;
        this.refresh = b.refresh;
        this.maxBodySize = b.maxBodySize;
        this.clock = b.clock;
        for (RecordedExchange e : b.exchanges) {
            if (!e.replayable()) continue;
            flows.computeIfAbsent(key(e.method(), e.url(), e.requestBody(), e::requestHeader), k -> new ArrayDeque<>())
                    .add(e);
        }
    }

    /**
     * Starts a builder with no recordings and mitmproxy's defaults.
     *
     * @return a new builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * What happens to requests without a recording, as mitmproxy's {@code server_replay_extra}.
     *
     * @param kind {@code forward}, {@code kill} or {@code status}
     * @param status the status to answer with, for {@code status}
     */
    public record Extra(String kind, int status) {

        /** Checks the parts. */
        public Extra {
            if (!List.of("forward", "kill", "status").contains(kind)) throw new IllegalArgumentException("unknown kind " + kind);
            if (kind.equals("status") && (status < 100 || status > 999)) {
                throw new IllegalArgumentException("invalid HTTP status code: " + status);
            }
        }

        /** {@return sending the request on to the server (the default)} */
        public static Extra forward() {
            return new Extra("forward", 0);
        }

        /** {@return closing the connection without a response} */
        public static Extra kill() {
            return new Extra("kill", 0);
        }

        /**
         * Answering with an empty response.
         *
         * @param status the status to answer with
         * @return the behaviour
         */
        public static Extra status(int status) {
            return new Extra("status", status);
        }

        /**
         * Parses {@code forward}, {@code kill} or a status code.
         *
         * @param value the option value
         * @return the behaviour
         * @throws IllegalArgumentException for anything else
         */
        public static Extra parse(String value) {
            String v = value.strip().toLowerCase(Locale.ROOT);
            if (v.equals("forward")) return forward();
            if (v.equals("kill")) return kill();
            try {
                return status(Integer.parseInt(v));
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("expected forward, kill or a status code, got " + value, e);
            }
        }
    }

    /**
     * A response answered from a recording, which the proxy reports as {@link
     * ResponseSource#REPLAY}.
     */
    public static final class Replayed extends DefaultFullHttpResponse {
        Replayed(HttpResponseStatus status, byte[] content) {
            super(HttpVersion.HTTP_1_1, status, content);
        }
    }

    /** {@return how many recorded responses are left to replay (all of them, with reuse)} */
    public int remaining() {
        lock.lock();
        try {
            return flows.values().stream().mapToInt(Deque::size).sum();
        } finally {
            lock.unlock();
        }
    }

    @Override
    public HttpFilters filterRequest(HttpRequest originalRequest, FlowContext flowContext) {
        if (HttpMethod.CONNECT.equals(originalRequest.method())) return null;
        return new Filters(originalRequest, flowContext);
    }

    private final class Filters extends AddonFilters {
        private HttpResponse kill;

        Filters(HttpRequest original, FlowContext ctx) {
            super(original, ctx);
        }

        @Override
        public int requestBufferSizeInBytes(HttpRequest head) {
            return !ignoreContent && unbufferedBody(head) ? maxBodySize : 0;
        }

        @Override
        public HttpResponse clientToProxyRequest(HttpObject httpObject) {
            if (!(httpObject instanceof HttpRequest r)) return null;
            request = r;
            String url = Specs.url(r, ctx);
            byte[] body = r instanceof FullHttpRequest full ? full.content() : new byte[0];
            RecordedExchange recorded = next(key(r.method().name(), url, body, r.headers()::get));
            if (recorded != null) return replay(recorded);
            return switch (extra.kind()) {
                case "kill" -> {
                    LOG.log(Level.WARNING, "server replay: killed non-replay request " + url);
                    kill = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.valueOf(444));
                    yield kill;
                }
                case "status" -> {
                    LOG.log(Level.WARNING, "server replay: returned " + extra.status() + " for non-replay request " + url);
                    yield new Replayed(HttpResponseStatus.valueOf(extra.status()), new byte[0]);
                }
                default -> null;
            };
        }

        @Override
        public HttpObject proxyToClientResponse(HttpObject httpObject) {
            return httpObject == kill ? null : httpObject;
        }
    }

    /** The next recording for {@code key}, used up unless reusing; null if none is left. */
    private RecordedExchange next(List<String> key) {
        lock.lock();
        try {
            Deque<RecordedExchange> list = flows.get(key);
            if (list == null || list.isEmpty()) return null;
            if (reuse) return list.peekFirst();
            RecordedExchange e = list.pollFirst();
            if (list.isEmpty()) flows.remove(key);
            return e;
        } finally {
            lock.unlock();
        }
    }

    /** A copy of the recorded response, refreshed for now. */
    private HttpResponse replay(RecordedExchange e) {
        HttpResponseStatus status;
        try {
            status = e.reason().isBlank() ? HttpResponseStatus.valueOf(e.status())
                    : HttpResponseStatus.valueOf(e.status(), e.reason());
        } catch (IllegalArgumentException ex) {
            status = HttpResponseStatus.valueOf(e.status());
        }
        Replayed response = new Replayed(status, e.responseBody().clone());
        Duration delta = refresh && e.started() != null ? Duration.between(e.started(), clock.instant()) : null;
        for (Map.Entry<String, String> h : e.responseHeaders()) {
            String name = h.getKey();
            if (RecordedExchange.framing(name) || hopByHop(name)) continue;
            String value = delta == null ? h.getValue() : refreshed(name, h.getValue(), delta);
            try {
                response.headers().add(name, value);
            } catch (IllegalArgumentException ex) {
                LOG.log(Level.DEBUG, "server replay: dropping invalid recorded header " + name);
            }
        }
        HttpUtil.setContentLength(response, response.content().length);
        return response;
    }

    private static boolean hopByHop(String name) {
        return switch (name.toLowerCase(Locale.ROOT)) {
            case "connection", "keep-alive", "proxy-connection", "upgrade", "te", "trailer" -> true;
            default -> false;
        };
    }

    private static final DateTimeFormatter HTTP_DATE = DateTimeFormatter.RFC_1123_DATE_TIME.withZone(ZoneOffset.UTC);

    /** {@code value} with its dates moved by {@code delta}, for the headers {@code refresh} adjusts. */
    static String refreshed(String name, String value, Duration delta) {
        String lower = name.toLowerCase(Locale.ROOT);
        if (lower.equals("date") || lower.equals("expires") || lower.equals("last-modified")) {
            Instant at = Cookies.parseDate(value);
            return at == null ? value : HTTP_DATE.format(at.plus(delta));
        }
        if (lower.equals("set-cookie")) {
            StringBuilder out = new StringBuilder();
            for (String part : value.split(";", -1)) {
                if (!out.isEmpty()) out.append(';');
                String p = part.strip();
                if (p.regionMatches(true, 0, "expires=", 0, 8)) {
                    Instant at = Cookies.parseDate(p.substring(8));
                    if (at == null) continue; // an invalid expires is dropped, as mitmproxy does
                    out.append(" Expires=").append(HTTP_DATE.format(at.plus(delta)));
                } else {
                    out.append(out.isEmpty() ? p : " " + p);
                }
            }
            return out.toString();
        }
        return value;
    }

    /**
     * The matching key of a request, after mitmproxy's {@code _hash}: scheme, method, path, the
     * body (or its form fields), host, port, query parameters and chosen headers, as the options
     * say.
     */
    private List<String> key(String method, String url, byte[] body, java.util.function.Function<String, String> header) {
        List<String> key = new ArrayList<>();
        String scheme = Specs.scheme(url);
        int start = url.indexOf("://") + 3;
        int pathStart = start;
        while (pathStart < url.length() && "/?#".indexOf(url.charAt(pathStart)) < 0) pathStart++;
        String authority = url.substring(start, pathStart);
        int at = authority.lastIndexOf('@');
        if (at >= 0) authority = authority.substring(at + 1);
        int pathEnd = pathStart;
        while (pathEnd < url.length() && url.charAt(pathEnd) != '?' && url.charAt(pathEnd) != '#') pathEnd++;
        String path = url.substring(pathStart, pathEnd);
        key.add(scheme);
        key.add(method.toUpperCase(Locale.ROOT));
        key.add(path.isEmpty() ? "/" : path);
        if (!ignoreContent) {
            String type = header.apply("Content-Type");
            boolean form = type != null && type.toLowerCase(Locale.ROOT).startsWith("application/x-www-form-urlencoded");
            if (!ignorePayloadParams.isEmpty() && form) {
                for (Map.Entry<String, String> p : HarRecorder.parseForm(new String(body, ISO_8859_1))) {
                    if (!ignorePayloadParams.contains(p.getKey())) {
                        key.add(p.getKey());
                        key.add(p.getValue());
                    }
                }
            } else {
                key.add(new String(body, ISO_8859_1));
            }
        }
        String host = FlowFilter.urlHost(url);
        if (!ignoreHost) key.add(host);
        if (!ignorePort) {
            int colon = authority.lastIndexOf(':');
            String port = colon > authority.lastIndexOf(']') ? authority.substring(colon + 1)
                    : scheme.equals("https") ? "443" : "80";
            key.add(port);
        }
        for (Map.Entry<String, String> p : HarRecorder.parseForm(HarRecorder.query(url))) {
            if (ignoreParams.contains(p.getKey())) continue;
            key.add(p.getKey());
            key.add(p.getValue());
        }
        for (String name : useHeaders) {
            key.add(name.toLowerCase(Locale.ROOT));
            key.add(String.valueOf(header.apply(name)));
        }
        return key;
    }

    /** Configures a {@link ServerReplay}. */
    public static final class Builder {
        private final List<RecordedExchange> exchanges = new ArrayList<>();
        private boolean ignoreContent;
        private boolean ignoreHost;
        private boolean ignorePort;
        private final Set<String> ignoreParams = new LinkedHashSet<>();
        private final Set<String> ignorePayloadParams = new LinkedHashSet<>();
        private final List<String> useHeaders = new ArrayList<>();
        private boolean reuse;
        private Extra extra = Extra.forward();
        private boolean refresh = true;
        private int maxBodySize = 16 << 20;
        private Clock clock = Clock.systemUTC();

        private Builder() {}

        /**
         * Adds the exchanges recorded in a HAR or WARC file, or in every such file of a directory
         * (see {@link RecordedExchange#load}).
         *
         * @param path a file or directory
         * @return this builder
         * @throws IOException if a file cannot be read or is in neither format
         */
        public Builder load(Path path) throws IOException {
            exchanges.addAll(RecordedExchange.load(path));
            return this;
        }

        /**
         * Adds recorded exchanges.
         *
         * @param recorded the exchanges, in recorded order
         * @return this builder
         */
        public Builder add(Collection<RecordedExchange> recorded) {
            exchanges.addAll(recorded);
            return this;
        }

        /**
         * Ignores request bodies when matching (default false).
         *
         * @param ignore whether to ignore bodies
         * @return this builder
         */
        public Builder ignoreContent(boolean ignore) {
            this.ignoreContent = ignore;
            return this;
        }

        /**
         * Ignores the host when matching (default false).
         *
         * @param ignore whether to ignore the host
         * @return this builder
         */
        public Builder ignoreHost(boolean ignore) {
            this.ignoreHost = ignore;
            return this;
        }

        /**
         * Ignores the port when matching (default false).
         *
         * @param ignore whether to ignore the port
         * @return this builder
         */
        public Builder ignorePort(boolean ignore) {
            this.ignorePort = ignore;
            return this;
        }

        /**
         * Query parameters to ignore when matching.
         *
         * @param names parameter names
         * @return this builder
         */
        public Builder ignoreParams(String... names) {
            ignoreParams.addAll(List.of(names));
            return this;
        }

        /**
         * Form fields of {@code application/x-www-form-urlencoded} bodies to ignore when matching;
         * the other fields are compared instead of the whole body.
         *
         * @param names field names
         * @return this builder
         */
        public Builder ignorePayloadParams(String... names) {
            ignorePayloadParams.addAll(List.of(names));
            return this;
        }

        /**
         * Request headers that must match too.
         *
         * @param names header names
         * @return this builder
         */
        public Builder useHeaders(String... names) {
            useHeaders.addAll(List.of(names));
            return this;
        }

        /**
         * Keeps answering with a recording rather than using it up (default false: each answers once).
         *
         * @param reuse whether recordings can be replayed any number of times
         * @return this builder
         */
        public Builder reuse(boolean reuse) {
            this.reuse = reuse;
            return this;
        }

        /**
         * What happens to requests without a recording (default {@link Extra#forward()}).
         *
         * @param extra forward, kill or a status
         * @return this builder
         */
        public Builder extra(Extra extra) {
            this.extra = Objects.requireNonNull(extra, "extra");
            return this;
        }

        /**
         * Shifts the dates of replayed responses by the time since they were recorded (default true).
         *
         * @param refresh whether to refresh dates
         * @return this builder
         */
        public Builder refresh(boolean refresh) {
            this.refresh = refresh;
            return this;
        }

        /**
         * Largest request body buffered to compare it (default 16 MiB); a larger one is answered
         * with {@code 413}, unless bodies are ignored.
         *
         * @param bytes the buffer limit
         * @return this builder
         */
        public Builder maxBodySize(int bytes) {
            if (bytes <= 0) throw new IllegalArgumentException("must be positive");
            this.maxBodySize = bytes;
            return this;
        }

        /** For tests: the clock {@code refresh} reads. */
        Builder clock(Clock clock) {
            this.clock = Objects.requireNonNull(clock);
            return this;
        }

        /**
         * Creates the addon.
         *
         * @return the configured addon
         */
        public ServerReplay build() {
            return new ServerReplay(this);
        }
    }

}
