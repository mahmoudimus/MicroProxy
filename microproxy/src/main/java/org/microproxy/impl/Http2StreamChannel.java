package org.microproxy.impl;

import io.github.mahmoudimus.http2.HeaderField;
import io.github.mahmoudimus.http2.Http2Headers;
import java.io.EOFException;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.SocketTimeoutException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.Condition;
import org.microproxy.http.DefaultHttpContent;
import org.microproxy.http.DefaultLastHttpContent;
import org.microproxy.http.FullHttpMessage;
import org.microproxy.http.FullHttpResponse;
import org.microproxy.http.HttpContent;
import org.microproxy.http.HttpHeaderNames;
import org.microproxy.http.HttpHeaders;
import org.microproxy.http.HttpRequest;
import org.microproxy.http.HttpResponse;
import org.microproxy.http.HttpResponseStatus;
import org.microproxy.http.HttpUtil;
import org.microproxy.http.HttpVersion;
import org.microproxy.http.LastHttpContent;

/**
 * One HTTP/2 stream as a {@link ClientChannel}: the client side of one exchange, run on the
 * stream's own thread while the connection's other streams run on theirs.
 *
 * <p>The request body is the stream's DATA frames, which the connection's reader buffers here
 * (never more than the stream's flow-control window) and the exchange reads. The response head
 * becomes a HEADERS frame without HTTP/1's connection-specific fields, its body DATA frames that
 * wait for send window, and its trailers a final HEADERS frame.
 *
 * <p>What has no meaning in HTTP/2: there is no connection to keep alive or close ({@link
 * #clientKeepAlive} is always true, {@link #setKeepAlive} does nothing, and {@link #close} resets
 * the stream), framing is the protocol's ({@link #adaptFraming} only drops {@code
 * Transfer-Encoding}), and there are no protocol switches or tunnels ({@link #relay} resets the
 * stream; {@code CONNECT} is answered with 501 before it gets that far). A {@code 100 Continue} is
 * sent only to a client that asked for it; other interim responses are forwarded as interim
 * HEADERS.
 */
final class Http2StreamChannel extends Http2Endpoint.Stream implements ClientChannel {

    private static final Object CANCELLED = new Object();

    final Http2Connection connection;
    private final ClientFlowContext flow;
    private final String logPrefix;
    /** The request as the client sent it. */
    final HttpRequest request;
    private final boolean expectsContinue;
    private final Body body = new Body();

    // Guarded by connection.stateLock.
    final Condition changed;
    final ArrayDeque<byte[]> inbound = new ArrayDeque<>();
    /** Bytes of the first inbound chunk already read. */
    private int headOffset;
    /** Request bytes buffered and not yet read. */
    long buffered;
    /** Request data bytes received (for content-length). */
    long received;
    /** Bytes read (or padding received) and not yet credited back to the stream's window. */
    int unacked;
    final long declaredLength;
    private final boolean emptyRequest;
    /** END_STREAM received: the request is complete. */
    boolean remoteClosed;
    HttpHeaders trailers;
    /** END_STREAM has been sent: the response is complete. */
    volatile boolean responseEnded;

    // The stream thread's own.
    private boolean headersSent;
    private boolean continueSent;
    private boolean bodyAllowed = true;
    private final AtomicReference<Object> server = new AtomicReference<>();

    Http2StreamChannel(Http2Connection connection, int id, ClientFlowContext flow, HttpRequest request,
            long declaredLength, boolean endStream) {
        this.connection = connection;
        this.id = id;
        this.flow = flow;
        this.logPrefix = connection.logPrefix.substring(0, connection.logPrefix.length() - 2) + " stream " + id + "] ";
        this.request = request;
        this.expectsContinue = HttpUtil.is100ContinueExpected(request);
        this.changed = connection.stateLock.newCondition();
        this.declaredLength = declaredLength;
        this.emptyRequest = endStream;
        this.remoteClosed = endStream;
    }

    /** Marks the stream reset; holds stateLock. */
    void markReset(IOException cause) {
        reset = true;
        resetCause = cause;
        changed.signalAll();
    }

    /** What the exchange's waits and writes fail with once the stream is reset. */
    @Override
    IOException failure() {
        IOException cause = resetCause;
        return new ClientConnection.ClientFailure(cause != null ? cause : new EOFException("stream " + id + " reset"));
    }

    /** The client cancelled the stream: the server connection in use, to close, or null. */
    ServerConnection cancelServer() {
        Object previous = server.getAndSet(CANCELLED);
        return previous instanceof ServerConnection c ? c : null;
    }

    // ---------------------------------------------------------------------------------------
    // ClientChannel
    // ---------------------------------------------------------------------------------------

    @Override
    public ClientFlowContext flowContext() {
        return flow;
    }

    @Override
    public String logPrefix() {
        return logPrefix;
    }

    @Override
    public boolean multiplexed() {
        return true;
    }

    @Override
    public boolean supportsTunnels() {
        return false;
    }

    @Override
    public void serverConnectionInUse(ServerConnection conn) throws IOException {
        while (true) {
            Object current = server.get();
            if (current == CANCELLED) throw failure();
            if (server.compareAndSet(current, conn)) return;
        }
    }

    @Override
    public boolean serverConnectionDone(ServerConnection conn) {
        return server.compareAndSet(conn, null) || server.get() != CANCELLED;
    }

    @Override
    public MessageBody requestBody(HttpRequest request) {
        return body;
    }

    @Override
    public boolean clientKeepAlive(HttpRequest request) {
        return true;
    }

    @Override
    public void awaitUnlessClientLeaves(long deadline) throws IOException {
        connection.stateLock.lock();
        try {
            long remaining;
            while (!reset && (remaining = deadline - System.nanoTime()) > 0) {
                changed.awaitNanos(remaining);
            }
            if (reset) throw failure();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new InterruptedIOException("interrupted while waiting to retry");
        } finally {
            connection.stateLock.unlock();
        }
    }

    @Override
    public void writeContinue() throws IOException {
        if (!expectsContinue || continueSent || headersSent) return;
        continueSent = true;
        connection.writeHeaders(this, List.of(new HeaderField(":status", "100")), false);
    }

    @Override
    public void writeInformational(HttpResponse response) throws IOException {
        int code = response.status().code();
        if (code == 100) {
            writeContinue();
        } else if (code > 101 && code < 200 && !headersSent) {
            // 102, 103 (Early Hints): interim HEADERS before the final response (RFC 9113 section 8.1).
            connection.writeHeaders(this, responseFields(code, response.headers()), false);
        }
    }

    @Override
    public boolean adaptFraming(HttpResponse response, boolean streamed) {
        // DATA frames delimit the body, so the stream never closes to end it.
        response.headers().remove(HttpHeaderNames.TRANSFER_ENCODING);
        return false;
    }

    @Override
    public void setKeepAlive(HttpResponse response, boolean keepAlive) {
        // No connection-specific fields in HTTP/2; the connection outlives every stream.
    }

    @Override
    public void setUpgrade(HttpResponse response, String upgrade) {
        // HTTP/2 has no protocol switch; relay() resets the stream.
    }

    @Override
    public void writeHead(HttpResponse response, boolean bodyAllowed) throws IOException {
        if (response instanceof FullHttpMessage full) {
            writeFull(response, full, bodyAllowed);
            return;
        }
        this.bodyAllowed = bodyAllowed;
        sendHead(response, !bodyAllowed);
    }

    @Override
    public void writeComplete(HttpResponse response, boolean bodyAllowed) throws IOException {
        if (response instanceof FullHttpMessage full) {
            writeFull(response, full, bodyAllowed);
            return;
        }
        if (bodyAllowed && !response.headers().contains(HttpHeaderNames.CONTENT_LENGTH)) {
            HttpUtil.setContentLength(response, 0);
        }
        this.bodyAllowed = false;
        sendHead(response, true);
    }

    private void writeFull(HttpResponse response, FullHttpMessage full, boolean bodyAllowed) throws IOException {
        byte[] content = full.content();
        HttpHeaders trailing = full.trailingHeaders();
        if (bodyAllowed) {
            response.headers().remove(HttpHeaderNames.TRANSFER_ENCODING);
            HttpUtil.setContentLength(response, content.length);
        }
        this.bodyAllowed = false;
        if (!bodyAllowed || (content.length == 0 && trailing.isEmpty())) {
            sendHead(response, true);
            return;
        }
        sendHead(response, false);
        sendData(content, 0, content.length, trailing.isEmpty(), true);
        if (!trailing.isEmpty()) sendTrailers(trailing);
    }

    @Override
    public void writeContent(HttpContent content) throws IOException {
        if (!bodyAllowed || responseEnded) return;
        byte[] data = content.content();
        boolean last = content instanceof LastHttpContent;
        HttpHeaders trailing = last ? ((LastHttpContent) content).trailingHeaders() : null;
        boolean endWithData = last && trailing.isEmpty();
        if (data.length > 0 || endWithData) {
            sendData(data, 0, data.length, endWithData, true);
        }
        if (last && !trailing.isEmpty()) sendTrailers(trailing);
    }

    @Override
    public void writeData(byte[] data, int off, int len) throws IOException {
        if (!bodyAllowed || responseEnded || len == 0) return;
        sendData(data, off, len, false, false);
    }

    @Override
    public void flush() throws IOException {
        connection.flush();
    }

    @Override
    public void writeEnd(HttpHeaders trailing) throws IOException {
        if (!bodyAllowed || responseEnded) {
            connection.flush();
            return;
        }
        if (trailing != null && !trailing.isEmpty()) {
            sendTrailers(trailing);
        } else {
            sendData(new byte[0], 0, 0, true, true);
        }
    }

    @Override
    public void relay(ServerConnection conn, Tunnel.FrameHandler frames, String name) {
        // Nothing to relay on a stream: a server that switched protocols cannot reach this client.
        close();
    }

    @Override
    public void reject(HttpResponseStatus status) {
        FullHttpResponse response = ProxyUtils.createFullHttpResponse(HttpVersion.HTTP_1_1, status, status.reasonPhrase());
        try {
            writeComplete(response, true);
        } catch (IOException ignored) {
            // the stream is reset below
        }
        close();
    }

    @Override
    public void close() {
        connection.closeStream(this);
    }

    // ---------------------------------------------------------------------------------------
    // Writing
    // ---------------------------------------------------------------------------------------

    private void sendHead(HttpResponse response, boolean endStream) throws IOException {
        headersSent = true;
        connection.writeHeaders(this, responseFields(response.status().code(), response.headers()), endStream);
        if (endStream) responseEnded = true;
    }

    private void sendData(byte[] data, int off, int len, boolean endStream, boolean flush) throws IOException {
        connection.writeData(this, data, off, len, endStream, flush);
        if (endStream) responseEnded = true;
    }

    private void sendTrailers(HttpHeaders trailing) throws IOException {
        List<HeaderField> fields = responseFields(200, trailing);
        connection.writeHeaders(this, fields.subList(1, fields.size()), true);
        responseEnded = true;
    }

    /**
     * An HTTP/2 field list for a response head (or, without its {@code :status}, trailers): names
     * lower-cased, connection-specific fields dropped. Fields HTTP/2 cannot carry are dropped too.
     */
    static List<HeaderField> responseFields(int status, HttpHeaders headers) {
        List<Map.Entry<String, String>> entries = headers.entries();
        try {
            return Http2Headers.fromHttp1Response(status, entries);
        } catch (IllegalArgumentException e) {
            List<Map.Entry<String, String>> valid = new ArrayList<>(entries.size());
            for (Map.Entry<String, String> entry : entries) {
                try {
                    Http2Headers.fromHttp1Response(status, List.of(entry));
                    valid.add(entry);
                } catch (IllegalArgumentException invalid) {
                    // dropped
                }
            }
            return Http2Headers.fromHttp1Response(status, valid);
        }
    }

    // ---------------------------------------------------------------------------------------
    // The request body: the stream's DATA frames
    // ---------------------------------------------------------------------------------------

    private final class Body implements MessageBody {
        /** The end has been returned to the exchange. */
        private boolean done;

        @Override
        public boolean hasBody() {
            return !emptyRequest && declaredLength != 0;
        }

        @Override
        public long declaredLength() {
            return declaredLength;
        }

        @Override
        public boolean isDone() {
            connection.stateLock.lock();
            try {
                return done || (remoteClosed && inbound.isEmpty());
            } finally {
                connection.stateLock.unlock();
            }
        }

        @Override
        public HttpContent next() throws IOException {
            if (done) return null;
            byte[] chunk;
            connection.stateLock.lock();
            try {
                chunk = awaitChunk();
                if (chunk == null) {
                    done = true;
                    HttpHeaders t = trailers;
                    return t == null || t.isEmpty() ? LastHttpContent.empty() : new DefaultLastHttpContent(new byte[0], t);
                }
                inbound.pollFirst();
                if (headOffset > 0) {
                    chunk = java.util.Arrays.copyOfRange(chunk, headOffset, chunk.length);
                    headOffset = 0;
                }
                buffered -= chunk.length;
            } finally {
                connection.stateLock.unlock();
            }
            connection.consumed(Http2StreamChannel.this, chunk.length);
            return new DefaultHttpContent(chunk);
        }

        @Override
        public int read(byte[] dst, int off, int len) throws IOException {
            if (done) return -1;
            int n;
            connection.stateLock.lock();
            try {
                byte[] chunk = awaitChunk();
                if (chunk == null) {
                    done = true;
                    return -1;
                }
                n = Math.min(len, chunk.length - headOffset);
                System.arraycopy(chunk, headOffset, dst, off, n);
                headOffset += n;
                if (headOffset == chunk.length) {
                    inbound.pollFirst();
                    headOffset = 0;
                }
                buffered -= n;
            } finally {
                connection.stateLock.unlock();
            }
            connection.consumed(Http2StreamChannel.this, n);
            return n;
        }

        /** The first buffered chunk, waiting for one; null at the end of the body. Holds stateLock. */
        private byte[] awaitChunk() throws IOException {
            int idle = connection.server.idleTimeoutMillis();
            long remaining = idle > 0 ? TimeUnit.MILLISECONDS.toNanos(idle) : Long.MAX_VALUE;
            try {
                while (inbound.isEmpty()) {
                    if (reset) throw failure();
                    if (remoteClosed) return null;
                    if (remaining <= 0) {
                        // As an HTTP/1 client connection's read times out.
                        throw new SocketTimeoutException("no request body from the client for " + idle + " ms");
                    }
                    remaining = changed.awaitNanos(remaining);
                }
                return inbound.peekFirst();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new InterruptedIOException("interrupted reading the request body");
            }
        }

        @Override
        public HttpHeaders trailers() {
            connection.stateLock.lock();
            try {
                return trailers != null ? trailers : new HttpHeaders();
            } finally {
                connection.stateLock.unlock();
            }
        }

        @Override
        public boolean hasBufferedInput() {
            connection.stateLock.lock();
            try {
                return !inbound.isEmpty();
            } finally {
                connection.stateLock.unlock();
            }
        }
    }
}
