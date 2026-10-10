/*
 * Ported from mitmproxy's mitmproxy/addons/savehar.py and strutils.is_mostly_bin in
 * mitmproxy/utils/strutils.py (https://github.com/mitmproxy/mitmproxy), Copyright (c) 2013, Aldo
 * Cortesi. Licensed under the MIT License; see META-INF/LICENSE-mitmproxy.txt. MicroProxy changes:
 * timings come from FlowTimings, bodies are captured as they stream past (up to a limit), and
 * entries can be streamed to the file instead of kept in memory.
 */
package org.microproxy.extras;

import static java.nio.charset.StandardCharsets.ISO_8859_1;
import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.OutputStream;
import java.io.Writer;
import java.lang.System.Logger.Level;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CodingErrorAction;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantLock;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import org.microproxy.FlowContext;
import org.microproxy.FlowTimings;
import org.microproxy.FullFlowContext;
import org.microproxy.HttpFilters;
import org.microproxy.HttpFiltersBuilder.Body;
import org.microproxy.HttpFiltersSource;
import org.microproxy.ResponseSource;
import org.microproxy.SelectiveFilters;
import org.microproxy.http.DefaultFullHttpRequest;
import org.microproxy.http.DefaultFullHttpResponse;
import org.microproxy.http.DefaultHttpRequest;
import org.microproxy.http.DefaultHttpResponse;
import org.microproxy.http.FullHttpMessage;
import org.microproxy.http.FullHttpRequest;
import org.microproxy.http.FullHttpResponse;
import org.microproxy.http.HttpBodies;
import org.microproxy.http.HttpContent;
import org.microproxy.http.HttpHeaderNames;
import org.microproxy.http.HttpHeaders;
import org.microproxy.http.HttpMessage;
import org.microproxy.http.HttpMethod;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;
import org.microproxy.http.HttpUtil;

/**
 * Records exchanges as an HTTP Archive (HAR 1.2), as mitmproxy's {@code hardump} / {@code
 * save.har} do, for browsers' developer tools, HAR viewers and {@link ServerReplay}.
 *
 * <pre>{@code
 * HarRecorder har = HarRecorder.builder(Path.of("flows.har")).build();
 * MicroProxy.bootstrap().withFiltersSource(HttpFiltersChain.of(har, otherFilters)).start();
 * ...
 * har.close();   // writes flows.har
 * }</pre>
 *
 * <p>Each entry holds the request as the client sent it (method, absolute URL, headers, cookies,
 * query string, {@code postData}) and the response as the client received it (status, headers,
 * cookies, content), whoever answered: the server, a filter, the cache, a replay or the proxy
 * ({@code _source} says which). Entries also carry the {@code serverIPAddress}, the client
 * connection id and {@link FlowTimings timings}: {@code dns}, {@code connect} (including {@code
 * ssl}), {@code send}, {@code wait} and {@code receive}; {@code -1} marks phases that did not happen,
 * such as connecting on a reused connection. Bodies are decoded (gzip, deflate, Brotli, zstd) and
 * written as text in their charset, or base64 ({@code "encoding": "base64"}) for binary content.
 * An exchange that ends without a response is written with status 0 and an {@code _error}.
 * {@code CONNECT} tunnels are not recorded; the requests inside intercepted sessions are.
 *
 * <p>Put the recorder first among the filters to record requests before other filters change
 * them. Bodies are captured as they stream past, up to {@link Builder#maxBodySize} each (larger
 * bodies are cut short and marked {@code _truncated}), which turns off the proxy's zero-copy body
 * relay; {@link Builder#content(boolean) content(false)} records heads only and keeps it.
 *
 * <p><b>Memory.</b> By default every entry, bodies included, is kept in memory until {@link
 * #close()} (or {@link #save}) writes the file, as mitmproxy does: a long session can take up to
 * twice {@code maxBodySize} per exchange (more for base64). {@link Builder#stream(boolean)
 * stream(true)} writes each entry to the file as it completes instead, holding nothing; the file
 * is valid JSON once closed. A file name ending in {@code .zhar} is written zlib-compressed.
 */
public final class HarRecorder implements HttpFiltersSource, Closeable {

    private static final System.Logger LOG = System.getLogger(HarRecorder.class.getName());

    private final Path path;
    private final FlowFilter filter;
    private final int maxBodySize;
    private final boolean content;
    private final ReentrantLock lock = new ReentrantLock();
    private final List<String> entries = new ArrayList<>();
    private final AtomicLong recorded = new AtomicLong();
    /** The address each server was last reached at, for requests on reused connections. */
    private final Map<String, String> serverIps = new ConcurrentHashMap<>();
    private final Writer stream;
    private boolean closed;

    private HarRecorder(Builder b) throws IOException {
        this.path = b.path;
        this.filter = b.filter;
        this.maxBodySize = b.maxBodySize;
        this.content = b.content;
        if (b.stream) {
            Path parent = path.toAbsolutePath().getParent();
            if (parent != null) Files.createDirectories(parent);
            stream = new java.io.BufferedWriter(new java.io.OutputStreamWriter(open(path), UTF_8));
            stream.write(header());
            stream.flush();
        } else {
            stream = null;
        }
    }

    /**
     * Starts a builder for a recorder that writes {@code path}.
     *
     * @param path the HAR file to write ({@code .zhar}: zlib-compressed)
     * @return a new builder with default settings
     */
    public static Builder builder(Path path) {
        return new Builder(path);
    }

    /** {@return the file this recorder writes} */
    public Path path() {
        return path;
    }

    /** {@return the number of entries recorded so far} */
    public long recordedEntries() {
        return recorded.get();
    }

    /**
     * Writes the entries recorded so far to {@code target} as a complete HAR file, replacing it
     * atomically. Recording goes on.
     *
     * @param target the file to write ({@code .zhar}: zlib-compressed)
     * @throws IOException if the file cannot be written
     * @throws IllegalStateException if the recorder streams its entries, and so keeps none
     */
    public void save(Path target) throws IOException {
        if (stream != null) throw new IllegalStateException("a streaming HAR recorder keeps no entries to save");
        List<String> snapshot;
        lock.lock();
        try {
            snapshot = List.copyOf(entries);
        } finally {
            lock.unlock();
        }
        Path parent = target.toAbsolutePath().getParent();
        if (parent != null) Files.createDirectories(parent);
        Path temp = Files.createTempFile(parent != null ? parent : Path.of("."), ".har-", ".tmp");
        try {
            try (Writer w = new java.io.BufferedWriter(new java.io.OutputStreamWriter(open(target, temp), UTF_8))) {
                w.write(header());
                for (int i = 0; i < snapshot.size(); i++) {
                    if (i > 0) w.write(",\n");
                    w.write(snapshot.get(i));
                }
                w.write(FOOTER);
            }
            Files.move(temp, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } finally {
            Files.deleteIfExists(temp);
        }
    }

    /** Writes the HAR file (or finishes the streamed one). Later exchanges are not recorded. */
    @Override
    public void close() throws IOException {
        lock.lock();
        try {
            if (closed) return;
            closed = true;
            if (stream != null) {
                stream.write(FOOTER);
                stream.close();
                return;
            }
        } finally {
            lock.unlock();
        }
        save(path);
    }

    private static final String FOOTER = "\n]}}\n";

    private static String header() {
        String version = HarRecorder.class.getPackage().getImplementationVersion();
        return "{\"log\":{\"version\":\"1.2\",\"creator\":{\"name\":\"MicroProxy\",\"version\":"
                + Json.string(version != null ? version : "unknown") + "},\"pages\":[],\"entries\":[\n";
    }

    private static OutputStream open(Path target) throws IOException {
        return open(target, target);
    }

    /** Opens {@code file} for a HAR named {@code name}: compressed for {@code .zhar}. */
    private static OutputStream open(Path name, Path file) throws IOException {
        OutputStream out = Files.newOutputStream(file);
        return name.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".zhar")
                ? new DeflaterOutputStream(out, new Deflater(9)) : out;
    }

    private void add(String entry) {
        lock.lock();
        try {
            if (closed) return;
            if (stream != null) {
                try {
                    if (recorded.get() > 0) stream.write(",\n");
                    stream.write(entry);
                    stream.flush();
                } catch (IOException e) {
                    LOG.log(Level.WARNING, "cannot write HAR entry to " + path + ": " + e.getMessage());
                    return;
                }
            } else {
                entries.add(entry);
            }
            recorded.incrementAndGet();
        } finally {
            lock.unlock();
        }
    }

    @Override
    public HttpFilters filterRequest(HttpRequest originalRequest, FlowContext flowContext) {
        if (HttpMethod.CONNECT.equals(originalRequest.method())) return null;
        return new Recording(flowContext);
    }

    /** A body as it streams past: the first {@code maxBodySize} bytes, and the total length. */
    private final class Capture {
        final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        long total;

        void add(byte[] data) {
            total += data.length;
            int room = maxBodySize - bytes.size();
            if (room > 0) bytes.write(data, 0, Math.min(room, data.length));
        }

        boolean truncated() {
            return total > bytes.size();
        }
    }

    /** One exchange being recorded. */
    private final class Recording implements SelectiveFilters {
        private final FlowContext ctx;
        private HttpRequest request;
        private String url;
        private Capture requestBody;
        private HttpResponse response;
        private Capture responseBody;
        private String serverIp;
        private boolean written;

        Recording(FlowContext ctx) {
            this.ctx = ctx;
        }

        @Override
        public boolean sees(Body stream) {
            return content && (stream == Body.REQUEST || stream == Body.RESPONSE);
        }

        @Override
        public HttpResponse clientToProxyRequest(HttpObject httpObject) {
            if (httpObject instanceof HttpRequest r && request == null) {
                request = new DefaultHttpRequest(r.protocolVersion(), r.method(), r.uri(), r.headers().copy());
                url = Specs.url(r, ctx);
                requestBody = new Capture();
            }
            if (httpObject instanceof FullHttpMessage full && requestBody != null) {
                requestBody.add(full.content());
            } else if (httpObject instanceof HttpContent piece && requestBody != null) {
                requestBody.add(piece.content());
            }
            return null;
        }

        @Override
        public void proxyToServerResolutionSucceeded(String hostAndPort, InetSocketAddress resolved) {
            if (resolved != null && resolved.getAddress() != null) serverIp = resolved.getAddress().getHostAddress();
        }

        @Override
        public void proxyToServerConnectionSucceeded(FullFlowContext serverContext) {
            InetSocketAddress remote = serverContext.getRemoteAddress();
            if (remote != null && remote.getAddress() != null) {
                serverIp = remote.getAddress().getHostAddress();
                if (serverIps.size() > 4096) serverIps.clear();
                serverIps.put(serverContext.getServerHostAndPort(), serverIp);
            }
        }

        @Override
        public HttpObject proxyToClientResponse(HttpObject httpObject) {
            if (request == null) return httpObject;
            if (httpObject instanceof HttpResponse r) {
                response = new DefaultHttpResponse(r.protocolVersion(), r.status(), r.headers().copy());
                responseBody = new Capture();
            }
            if (httpObject instanceof FullHttpMessage full && responseBody != null) {
                responseBody.add(full.content());
            } else if (httpObject instanceof HttpContent piece && responseBody != null) {
                responseBody.add(piece.content());
            }
            return httpObject;
        }

        @Override
        public void proxyToClientResponseSent(HttpResponse sent, ResponseSource source) {
            if (request == null || written) return;
            written = true;
            if (response == null) {
                response = new DefaultHttpResponse(sent.protocolVersion(), sent.status(), sent.headers().copy());
                responseBody = new Capture();
            }
            record(source, null);
        }

        @Override
        public void exchangeEnded(boolean completed) {
            if (request == null || written) return;
            written = true;
            response = null;
            record(null, "the exchange ended without a complete response");
        }

        private void record(ResponseSource source, String error) {
            try {
                if (filter != FlowFilter.ALL && !filter.matches(flowForFilter())) return;
                add(entry(source, error));
            } catch (RuntimeException e) {
                LOG.log(Level.WARNING, "cannot record " + url + " in HAR", e);
            }
        }

        private FlowFilter.Flow flowForFilter() {
            HttpRequest req = withBody(request, requestBody);
            HttpResponse res = response == null ? null : withBody(response, responseBody);
            return FlowFilter.flow(req, url, res);
        }

        private String entry(ResponseSource source, String error) {
            FlowTimings t = ctx != null ? ctx.timings() : FlowTimings.NONE;
            Instant started = t.start().orElse(Instant.now());
            Timings timings = Timings.of(t, source == ResponseSource.SERVER);
            if (serverIp == null && source == ResponseSource.SERVER) {
                serverIp = serverIps.get(hostAndPort(url));
            }
            Json e = new Json()
                    .field("startedDateTime", DateTimeFormatter.ISO_INSTANT.format(started))
                    .field("time", timings.total())
                    .raw("request", requestJson())
                    .raw("response", response == null ? errorResponseJson(error) : responseJson())
                    .raw("cache", "{}")
                    .raw("timings", timings.json());
            if (serverIp != null) e.field("serverIPAddress", serverIp);
            if (ctx != null) e.field("connection", String.valueOf(ctx.getConnectionId()));
            if (source != null) e.field("_source", source.name().toLowerCase(Locale.ROOT));
            return e.end();
        }

        private String requestJson() {
            String query = query(url);
            Json r = new Json()
                    .field("method", request.method().name())
                    .field("url", url)
                    .field("httpVersion", request.protocolVersion().text())
                    .raw("cookies", nameValues(cookies(request)))
                    .raw("headers", nameValues(request.headers().entries()))
                    .raw("queryString", nameValues(parseForm(query)))
                    .field("headersSize", headersSize(request.method().name() + " " + request.uri() + " "
                            + request.protocolVersion().text(), request.headers()))
                    .field("bodySize", content ? requestBody.total : Math.max(0, HttpUtil.getContentLength(request, 0)));
            if (requestBody.total > 0 && content) {
                String mime = request.headers().get(HttpHeaderNames.CONTENT_TYPE, "");
                Json post = new Json().field("mimeType", mime);
                BodyText text = bodyText(withBody(request, requestBody), requestBody);
                if (text.text != null) post.field("text", text.text);
                if (text.base64) post.field("encoding", "base64");
                if (requestBody.truncated()) post.field("_truncated", true);
                String type = HttpBodies.mediaType(request);
                post.raw("params", type.equals("application/x-www-form-urlencoded") && text.text != null && !text.base64
                        ? nameValues(parseForm(text.text)) : "[]");
                r.raw("postData", post.end());
            }
            return r.end();
        }

        private String responseJson() {
            String mime = response.headers().get(HttpHeaderNames.CONTENT_TYPE, "");
            Json c = new Json();
            long rawSize = content ? responseBody.total : Math.max(0, HttpUtil.getContentLength(response, 0));
            if (content) {
                BodyText text = bodyText(withBody(response, responseBody), responseBody);
                c.field("size", text.decodedSize >= 0 ? text.decodedSize : rawSize)
                        .field("compression", text.decodedSize >= 0 ? text.decodedSize - rawSize : 0)
                        .field("mimeType", mime);
                if (text.text != null) c.field("text", text.text);
                if (text.base64) c.field("encoding", "base64");
                if (text.stillEncoded) c.field("_contentEncoded", true);
                if (responseBody.truncated()) {
                    c.field("_truncated", true).field("comment", "body truncated at " + maxBodySize + " bytes");
                }
            } else {
                c.field("size", rawSize).field("compression", 0).field("mimeType", mime);
            }
            return new Json()
                    .field("status", response.status().code())
                    .field("statusText", response.status().reasonPhrase())
                    .field("httpVersion", response.protocolVersion().text())
                    .raw("cookies", responseCookies(response))
                    .raw("headers", nameValues(response.headers().entries()))
                    .raw("content", c.end())
                    .field("redirectURL", response.headers().get(HttpHeaderNames.LOCATION, ""))
                    .field("headersSize", headersSize(response.protocolVersion().text() + " " + response.status().code()
                            + " " + response.status().reasonPhrase(), response.headers()))
                    .field("bodySize", rawSize)
                    .end();
        }
    }

    private static String errorResponseJson(String error) {
        return new Json().field("status", 0).field("statusText", "").field("httpVersion", "")
                .raw("cookies", "[]").raw("headers", "[]").raw("content", "{\"size\":0,\"mimeType\":\"\"}")
                .field("redirectURL", "").field("headersSize", -1).field("bodySize", -1)
                .field("_error", error).end();
    }

    /** {@code request} as a full message with the captured body, for filters and decoding. */
    private static FullHttpRequest withBody(HttpRequest request, Capture body) {
        DefaultFullHttpRequest full = new DefaultFullHttpRequest(request.protocolVersion(), request.method(),
                request.uri(), body.bytes.toByteArray());
        full.headers().set(request.headers());
        return full;
    }

    /** {@code response} as a full message with the captured body, for filters and decoding. */
    private static FullHttpResponse withBody(HttpResponse response, Capture body) {
        DefaultFullHttpResponse full = new DefaultFullHttpResponse(response.protocolVersion(), response.status(),
                body.bytes.toByteArray());
        full.headers().set(response.headers());
        return full;
    }

    /**
     * A body as HAR content: text in the message's charset, or base64; {@code decodedSize} is -1
     * when the content codings could not be removed ({@code stillEncoded}).
     */
    private record BodyText(String text, boolean base64, long decodedSize, boolean stillEncoded) {}

    private static BodyText bodyText(FullHttpMessage message, Capture capture) {
        byte[] raw = message.content();
        byte[] decoded;
        boolean stillEncoded = false;
        try {
            decoded = capture.truncated() ? HttpBodies.decodedPrefix(message, Integer.MAX_VALUE) : HttpBodies.decoded(message);
        } catch (IOException e) {
            decoded = raw;
            stillEncoded = !HttpBodies.contentEncodings(message).isEmpty();
        }
        long size = stillEncoded ? -1 : decoded.length;
        if (decoded.length == 0) return new BodyText("", false, size, stillEncoded);
        if (!stillEncoded && !isMostlyBinary(decoded)) {
            Charset charset = HttpBodies.charset(message, UTF_8);
            try {
                String text = charset.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(decoded)).toString();
                return new BodyText(text, false, size, false);
            } catch (CharacterCodingException e) {
                // Not text in its charset after all: base64 below.
            }
        }
        return new BodyText(Base64.getEncoder().encodeToString(decoded), true, size, stillEncoded);
    }

    /**
     * mitmproxy's test for binary content, on (about) the first 100 bytes: text if more than 70%
     * is printable ASCII, or if it is UTF-8 with under 5% control characters.
     */
    static boolean isMostlyBinary(byte[] data) {
        if (data.length == 0) return false;
        int len = data.length;
        if (len > 100) {
            // Do not cut a UTF-8 sequence in half.
            len = 100;
            for (int cut = 100; cut < Math.min(104, data.length); cut++) {
                if ((data[cut] & 0xC0) != 0x80) {
                    len = cut;
                    break;
                }
            }
        }
        int low = 0;
        int high = 0;
        for (int i = 0; i < len; i++) {
            int b = data[i] & 0xff;
            if (b < 9 || (b > 13 && b < 32)) low++;
            else if (b > 126) high++;
        }
        int ascii = len - low - high;
        if (ascii > len * 0.7) return false;
        if (ascii + high > len * 0.95) {
            try {
                UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(data, 0, len));
                return false;
            } catch (CharacterCodingException e) {
                // Not UTF-8.
            }
        }
        return true;
    }

    /** The HAR timings of an exchange, in milliseconds; -1 for phases that did not happen. */
    private record Timings(double dns, double connect, double ssl, double send, double waiting, double receive) {

        static Timings of(FlowTimings t, boolean fromServer) {
            double dns = ms(t.dnsStartNanos(), t.dnsEndNanos());
            double tcp = ms(t.connectStartNanos(), t.connectEndNanos());
            double ssl = ms(t.tlsStartNanos(), t.tlsEndNanos());
            // HAR's connect includes the TLS handshake.
            double connect = tcp < 0 ? -1 : tcp + Math.max(0, ssl);
            if (!fromServer || t.firstResponseByteNanos() < 0) {
                double total = t.responseCompleteNanos() < 0 ? 0 : t.responseCompleteNanos() / 1e6;
                return new Timings(dns, connect, ssl, 0, 0, total);
            }
            long sendStart = Math.max(0, Math.max(t.dnsEndNanos(), Math.max(t.connectEndNanos(), t.tlsEndNanos())));
            long sent = t.requestSentNanos() >= 0 ? t.requestSentNanos() : t.firstResponseByteNanos();
            double send = Math.max(0, (sent - sendStart) / 1e6);
            double wait = Math.max(0, (t.firstResponseByteNanos() - sent) / 1e6);
            double receive = t.responseCompleteNanos() < 0 ? 0
                    : Math.max(0, (t.responseCompleteNanos() - t.firstResponseByteNanos()) / 1e6);
            return new Timings(dns, connect, ssl, send, wait, receive);
        }

        private static double ms(long start, long end) {
            return start < 0 || end < start ? -1 : (end - start) / 1e6;
        }

        /** The sum of the phases that happened ({@code ssl} is part of {@code connect}). */
        double total() {
            return Math.max(0, dns) + Math.max(0, connect) + send + waiting + receive;
        }

        String json() {
            return new Json().field("blocked", -1).field("dns", dns).field("connect", connect).field("send", send)
                    .field("wait", waiting).field("receive", receive).field("ssl", ssl).end();
        }
    }

    private static String nameValues(List<Map.Entry<String, String>> pairs) {
        List<String> out = new ArrayList<>(pairs.size());
        for (Map.Entry<String, String> p : pairs) {
            out.add(new Json().field("name", p.getKey()).field("value", p.getValue()).end());
        }
        return Json.array(out);
    }

    private static List<Map.Entry<String, String>> cookies(HttpRequest request) {
        List<Map.Entry<String, String>> out = new ArrayList<>();
        for (String header : request.headers().getAll("Cookie")) out.addAll(Cookies.parseCookieHeader(header));
        return out;
    }

    private static String responseCookies(HttpResponse response) {
        List<String> out = new ArrayList<>();
        for (String header : response.headers().getAll("Set-Cookie")) {
            Cookies.SetCookie c = Cookies.parseSetCookie(header);
            if (c == null) continue;
            Json j = new Json().field("name", c.name()).field("value", c.value())
                    .field("path", c.attributes().getOrDefault("path", "/"))
                    .field("domain", c.attributes().getOrDefault("domain", ""));
            String expires = c.attribute("expires");
            Instant at = expires == null ? null : Cookies.parseDate(expires);
            if (at != null) j.field("expires", DateTimeFormatter.ISO_INSTANT.format(at));
            j.field("httpOnly", c.attributes().containsKey("httponly")).field("secure", c.attributes().containsKey("secure"));
            if (c.attributes().containsKey("samesite")) j.field("sameSite", c.attribute("samesite"));
            out.add(j.end());
        }
        return Json.array(out);
    }

    /** The query of an absolute URL, without the {@code ?}; empty if none. */
    static String query(String url) {
        int q = url.indexOf('?');
        if (q < 0) return "";
        int hash = url.indexOf('#', q);
        return hash < 0 ? url.substring(q + 1) : url.substring(q + 1, hash);
    }

    /** {@code a=1&b=2} as decoded name-value pairs, keeping blanks and order. */
    static List<Map.Entry<String, String>> parseForm(String query) {
        List<Map.Entry<String, String>> out = new ArrayList<>();
        if (query.isEmpty()) return out;
        for (String pair : query.split("&")) {
            if (pair.isEmpty()) continue;
            int eq = pair.indexOf('=');
            out.add(Map.entry(decode(eq < 0 ? pair : pair.substring(0, eq)), decode(eq < 0 ? "" : pair.substring(eq + 1))));
        }
        return out;
    }

    private static String decode(String s) {
        try {
            return URLDecoder.decode(s, UTF_8);
        } catch (IllegalArgumentException e) {
            return s;
        }
    }

    private static long headersSize(String startLine, HttpHeaders headers) {
        long size = startLine.getBytes(ISO_8859_1).length + 2 + 2;
        for (Map.Entry<String, String> h : headers.entries()) {
            size += h.getKey().length() + 2 + h.getValue().getBytes(ISO_8859_1).length + 2;
        }
        return size;
    }

    /** {@code host:port} of an absolute URL, as the proxy names servers. */
    private static String hostAndPort(String url) {
        String host = FlowFilter.urlHost(url);
        int start = url.indexOf("://") + 3;
        int end = start;
        while (end < url.length() && "/?#".indexOf(url.charAt(end)) < 0) end++;
        String authority = url.substring(start, end);
        int colon = authority.lastIndexOf(':');
        String port = colon > authority.lastIndexOf(']') && colon >= 0 ? authority.substring(colon + 1)
                : Specs.scheme(url).equals("https") ? "443" : "80";
        return (host.indexOf(':') >= 0 ? "[" + host + "]" : host) + ":" + port;
    }

    /** Configures a {@link HarRecorder}. */
    public static final class Builder {
        private final Path path;
        private FlowFilter filter = FlowFilter.ALL;
        private int maxBodySize = 1 << 20;
        private boolean content = true;
        private boolean stream;

        private Builder(Path path) {
            this.path = Objects.requireNonNull(path, "path");
        }

        /**
         * Records only the exchanges {@code filter} matches (as mitmproxy's {@code
         * save_stream_filter}); default all. Body matchers see the captured bodies.
         *
         * @param filter the exchanges to record
         * @return this builder
         */
        public Builder filter(FlowFilter filter) {
            this.filter = Objects.requireNonNull(filter, "filter");
            return this;
        }

        /**
         * The most bytes kept of each body (default 1 MiB); the rest is counted but not recorded.
         *
         * @param bytes the limit per request or response body
         * @return this builder
         */
        public Builder maxBodySize(int bytes) {
            if (bytes < 0) throw new IllegalArgumentException("must not be negative");
            this.maxBodySize = bytes;
            return this;
        }

        /**
         * Whether to record bodies (default true). Without them the recorder reads heads only and
         * bodies keep the proxy's fast path; sizes then come from {@code Content-Length}.
         *
         * @param content whether to capture bodies
         * @return this builder
         */
        public Builder content(boolean content) {
            this.content = content;
            return this;
        }

        /**
         * Writes each entry to the file as it completes, rather than keeping entries in memory
         * until {@link HarRecorder#close()} (default false).
         *
         * @param stream whether to stream entries to the file
         * @return this builder
         */
        public Builder stream(boolean stream) {
            this.stream = stream;
            return this;
        }

        /**
         * Creates the recorder; a streaming one creates its file now.
         *
         * @return the recorder
         * @throws IOException if a streamed file cannot be created
         */
        public HarRecorder build() throws IOException {
            return new HarRecorder(this);
        }
    }
}
