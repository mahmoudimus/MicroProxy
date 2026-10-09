package org.microproxy.warc;

import java.io.Closeable;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.lang.System.Logger.Level;
import java.net.InetSocketAddress;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;
import org.microproxy.FlowContext;
import org.microproxy.HttpFilters;
import org.microproxy.HttpFiltersSource;
import org.microproxy.http.DefaultHttpRequest;
import org.microproxy.http.DefaultHttpResponse;
import org.microproxy.http.HttpContent;
import org.microproxy.http.HttpHeaderNames;
import org.microproxy.http.HttpHeaders;
import org.microproxy.http.HttpMethod;
import org.microproxy.http.HttpObject;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;

/**
 * Records the traffic between the proxy and servers as WARC 1.1 files (ISO 28500), the format web
 * archives use, so captures can be replayed with tools such as pywb or inspected with warcio.
 *
 * <pre>{@code
 * WarcRecorder recorder = WarcRecorder.builder(Path.of("warcs")).build();
 * MicroProxy.bootstrap().withFiltersSource(recorder).start();
 * ...
 * recorder.close();
 * }</pre>
 *
 * <p>Each exchange with a server becomes a {@code request} record and a {@code response} record
 * linked by {@code WARC-Concurrent-To}, with block and payload digests, the target URI ({@code
 * https://} inside intercepted sessions) and the server's IP address when known. Bodies are
 * captured as they stream past, without buffering the exchange: in memory, or in a temporary file
 * once large, up to {@link Builder#maxBodySize} (beyond that the record is marked {@code
 * WARC-Truncated: length}). Messages are recorded as exchanged except that chunked transfer coding
 * is removed and {@code Content-Length} states the recorded body length; content codings such as
 * gzip are kept.
 *
 * <p>Only traffic that reaches a server is recorded: responses from a cache or a filter are not,
 * and neither are tunnelled ({@code CONNECT}, not intercepted) bytes. Install the recorder first
 * among the filters to record messages before other filters change them.
 */
public final class WarcRecorder implements HttpFiltersSource, Closeable {

    private static final System.Logger LOG = System.getLogger(WarcRecorder.class.getName());

    private final WarcWriter writer;
    private final Path tempDir;
    private final long maxBodySize;
    private final AtomicLong recorded = new AtomicLong();
    private final AtomicLong failures = new AtomicLong();

    private WarcRecorder(Builder b) throws IOException {
        this.writer = new WarcWriter(b.dir, b.prefix, b.maxFileSize, b.compress, b.software);
        this.tempDir = b.dir;
        this.maxBodySize = b.maxBodySize;
    }

    /**
     * Starts a builder with the default settings.
     *
     * @param dir the directory in which to create WARC files
     * @return a new builder with default settings
     */
    public static Builder builder(Path dir) {
        return new Builder(dir);
    }

    /** Options for {@link WarcRecorder}. */
    public static final class Builder {
        private final Path dir;
        private String prefix = "microproxy";
        private long maxFileSize = 1L << 30;
        private long maxBodySize = 512L << 20;
        private boolean compress = true;
        private String software = "MicroProxy";

        private Builder(Path dir) {
            this.dir = Objects.requireNonNull(dir);
        }

        /**
         * File name prefix (default "microproxy").
         *
         * @param prefix the WARC file-name prefix
         * @return this builder
         */
        public Builder prefix(String prefix) {
            this.prefix = Objects.requireNonNull(prefix);
            return this;
        }

        /**
         * Start a new file after this many bytes (default 1 GiB).
         *
         * @param bytes the file size in bytes at which to rotate to a new WARC file
         * @return this builder
         */
        public Builder maxFileSize(long bytes) {
            this.maxFileSize = bytes;
            return this;
        }

        /**
         * Record at most this much of each body (default 512 MiB).
         *
         * @param bytes the maximum bytes to record from each body
         * @return this builder
         */
        public Builder maxBodySize(long bytes) {
            this.maxBodySize = bytes;
            return this;
        }

        /**
         * Gzip each record (default true).
         *
         * @param compress whether to gzip each WARC record
         * @return this builder
         */
        public Builder compress(boolean compress) {
            this.compress = compress;
            return this;
        }

        /**
         * The {@code software} field of the {@code warcinfo} records.
         *
         * @param software the software identification written to warcinfo records
         * @return this builder
         */
        public Builder software(String software) {
            this.software = Objects.requireNonNull(software);
            return this;
        }

        /**
         * Creates the configured WARC recorder.
         *
         * @return the configured WARC recorder
         * @throws IOException if the recording directory cannot be created
         */
        public WarcRecorder build() throws IOException {
            return new WarcRecorder(this);
        }
    }

    /** {@return exchanges recorded so far} */
    public long recordedExchanges() {
        return recorded.get();
    }

    /** {@return exchanges that could not be written} */
    public long failedExchanges() {
        return failures.get();
    }

    @Override
    public HttpFilters filterRequest(HttpRequest originalRequest, FlowContext flowContext) {
        if (originalRequest.method().equals(HttpMethod.CONNECT)) return null;
        return new Recording(originalRequest, flowContext);
    }

    /** Finishes the current WARC file. */
    @Override
    public void close() throws IOException {
        writer.close();
    }

    private final class Recording implements HttpFilters {
        private final String scheme;
        private String targetUri;
        private HttpRequest request;
        private Spool requestBody;
        private Instant requestDate;
        private HttpResponse response;
        private Spool responseBody;
        private Instant responseDate;
        private String serverIp;
        private boolean written;

        Recording(HttpRequest original, FlowContext ctx) {
            String uri = original.uri().toLowerCase(Locale.ROOT);
            this.scheme = uri.startsWith("https://") || (ctx != null && ctx.getClientSslSession() != null && !uri.startsWith("http://"))
                    ? "https" : "http";
        }

        @Override
        public HttpResponse proxyToServerRequest(HttpObject httpObject) {
            try {
                if (httpObject instanceof HttpRequest r) {
                    closeSpools();
                    request = copy(r);
                    targetUri = absolute(r);
                    requestDate = Instant.now();
                    requestBody = new Spool(tempDir, maxBodySize);
                    response = null;
                    written = false;
                }
                if (httpObject instanceof HttpContent c && requestBody != null) {
                    requestBody.add(c.content());
                }
            } catch (UncheckedIOException e) {
                abandon(e);
            }
            return null;
        }

        @Override
        public void proxyToServerResolutionSucceeded(String hostAndPort, InetSocketAddress resolved) {
            if (resolved != null && resolved.getAddress() != null) serverIp = resolved.getAddress().getHostAddress();
        }

        @Override
        public HttpObject serverToProxyResponse(HttpObject httpObject) {
            if (request == null) return httpObject;
            try {
                if (httpObject instanceof HttpResponse r) {
                    response = copy(r);
                    responseDate = Instant.now();
                    responseBody = new Spool(tempDir, maxBodySize);
                }
                if (httpObject instanceof HttpContent c && responseBody != null) {
                    responseBody.add(c.content());
                }
            } catch (UncheckedIOException e) {
                abandon(e);
            }
            return httpObject;
        }

        @Override
        public void serverToProxyResponseReceived() {
            if (request == null || response == null || written) return;
            written = true;
            try {
                writeExchange();
                recorded.incrementAndGet();
            } catch (IOException | UncheckedIOException e) {
                failures.incrementAndGet();
                LOG.log(Level.WARNING, "cannot record " + targetUri + " in WARC: " + e.getMessage());
            } finally {
                closeSpools();
            }
        }

        private void writeExchange() throws IOException {
            String responseId = WarcWriter.newId();
            String requestId = WarcWriter.newId();

            Map<String, String> responseFields = new LinkedHashMap<>();
            responseFields.put("WARC-Target-URI", targetUri);
            responseFields.put("WARC-IP-Address", serverIp);
            responseFields.put("WARC-Payload-Digest", responseBody.digest());
            if (responseBody.truncated()) responseFields.put("WARC-Truncated", "length");
            byte[] responseHead = WarcWriter.head(
                    response.protocolVersion().text() + " " + response.status().code() + " " + response.status().reasonPhrase(),
                    framed(response.headers(), responseBody));

            Map<String, String> requestFields = new LinkedHashMap<>();
            requestFields.put("WARC-Target-URI", targetUri);
            requestFields.put("WARC-Concurrent-To", responseId);
            requestFields.put("WARC-IP-Address", serverIp);
            requestFields.put("WARC-Payload-Digest", requestBody.digest());
            if (requestBody.truncated()) requestFields.put("WARC-Truncated", "length");
            byte[] requestHead = WarcWriter.head(
                    request.method().name() + " " + request.uri() + " " + request.protocolVersion().text(),
                    framed(request.headers(), requestBody));

            writer.write(List.of(
                    new WarcWriter.Record("response", responseId, responseDate, responseFields,
                            "application/http;msgtype=response", responseHead, responseBody),
                    new WarcWriter.Record("request", requestId, requestDate, requestFields,
                            "application/http;msgtype=request", requestHead, requestBody)));
        }

        private void abandon(UncheckedIOException e) {
            failures.incrementAndGet();
            LOG.log(Level.WARNING, "cannot record " + targetUri + " in WARC: " + e.getMessage());
            closeSpools();
            request = null;
        }

        private void closeSpools() {
            if (requestBody != null) requestBody.close();
            if (responseBody != null) responseBody.close();
        }

        private String absolute(HttpRequest r) {
            String uri = r.uri();
            String lower = uri.toLowerCase(Locale.ROOT);
            if (lower.startsWith("http://") || lower.startsWith("https://")) return uri;
            String host = r.headers().get(HttpHeaderNames.HOST, "");
            return scheme + "://" + host + (uri.startsWith("/") ? uri : "/" + uri);
        }
    }

    /** The headers with chunked framing replaced by the recorded length. */
    private static List<Map.Entry<String, String>> framed(HttpHeaders original, Spool body) {
        HttpHeaders h = original.copy();
        boolean chunked = h.getAllElements(HttpHeaderNames.TRANSFER_ENCODING).stream()
                .anyMatch(v -> v.equalsIgnoreCase("chunked"));
        if (chunked || h.contains(HttpHeaderNames.CONTENT_LENGTH) || body.size() > 0) {
            h.remove(HttpHeaderNames.TRANSFER_ENCODING);
            if (chunked || body.size() > 0 || body.truncated()) {
                h.set(HttpHeaderNames.CONTENT_LENGTH, String.valueOf(body.size()));
            }
        }
        return new ArrayList<>(h.entries());
    }

    private static HttpRequest copy(HttpRequest r) {
        return new DefaultHttpRequest(r.protocolVersion(), r.method(), r.uri(), r.headers().copy());
    }

    private static HttpResponse copy(HttpResponse r) {
        return new DefaultHttpResponse(r.protocolVersion(), r.status(), r.headers().copy());
    }
}
