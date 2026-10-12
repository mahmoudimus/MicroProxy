package org.microproxy.impl;

import io.github.mahmoudimus.http3.FieldSectionSizeException;
import io.github.mahmoudimus.http3.HeaderField;
import io.github.mahmoudimus.http3.Http3ErrorCode;
import io.github.mahmoudimus.http3.Http3Exception;
import io.github.mahmoudimus.http3.Http3FrameReader;
import io.github.mahmoudimus.http3.Http3Headers;
import io.github.mahmoudimus.http3.Http3StreamValidator;
import io.github.mahmoudimus.quic.QuicConnectionException;
import io.github.mahmoudimus.quic.QuicStream;
import io.github.mahmoudimus.quic.QuicStreamException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.lang.System.Logger.Level;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.IntConsumer;
import org.microproxy.FlowContext;
import org.microproxy.frames.FrameDirection;
import org.microproxy.frames.Http3Frame;
import org.microproxy.http.DefaultHttpContent;
import org.microproxy.http.DefaultLastHttpContent;
import org.microproxy.http.HttpContent;
import org.microproxy.http.HttpHeaders;
import org.microproxy.http.LastHttpContent;

/**
 * The receiving side of one HTTP/3 request stream: a client's request ({@link Http3Connection}),
 * or a server's response ({@link Http3UpstreamConnection}). A virtual thread of its own reads the
 * stream's frames, decodes header sections through the connection's QPACK decoder, shows each
 * frame to the frame interceptor, checks the message (frame order, {@code content-length}), and
 * queues what it read for the exchange: header sections ({@link #awaitHead}, {@link #takeHead}),
 * then the body ({@link #body()}), with its trailers.
 *
 * <p>The queue holds at most {@link #BUFFER} bytes of body beyond what the exchange has read:
 * past that the reading thread waits, and with it QUIC's flow control, which credits the peer only
 * for bytes read from the stream. So a peer never gets more than the stream's QUIC window and
 * this buffer ahead of the exchange, whatever an interceptor makes of its DATA.
 *
 * <p>A stream error (a malformed message) resets the stream both ways with its HTTP/3 code; a
 * connection error closes the connection. Either, and a reset by the peer, fail the exchange's
 * waits and reads with the cause.
 *
 * <p>A client's {@code CONNECT} (plain or extended) makes the stream a tunnel once answered: its
 * DATA are the tunnel's bytes ({@link #body()}, read with a timeout of their own, {@link
 * #setReadTimeout}), and a HEADERS frame after the request's is a connection error
 * H3_FRAME_UNEXPECTED (RFC 9114 section 4.4).
 */
final class Http3StreamReader {

    private static final System.Logger LOG = System.getLogger(Http3StreamReader.class.getName());

    /** Body bytes queued ahead of the exchange, at most (plus one frame's). */
    static final int BUFFER = 64 * 1024;

    /** A header section, or the head that was over the size limit ({@code fields} null). */
    record Head(List<HeaderField> fields) {
        boolean tooLarge() {
            return fields == null;
        }
    }

    private record Chunk(byte[] data) {}

    private record Trailers(List<HeaderField> fields) {}

    private record End() {}

    private final Http3Endpoint endpoint;
    final QuicStream stream;
    final long id;
    /** The frames are a server's response rather than a client's request. */
    private final boolean response;
    private final IntConsumer onBytes;
    /**
     * Told when the peer resets the stream (a client cancelling its request), before readers
     * waiting on the stream are.
     */
    private final Runnable onReset;

    private final ReentrantLock lock = new ReentrantLock();
    private final Condition changed = lock.newCondition();
    // Guarded by lock.
    private final ArrayDeque<Object> events = new ArrayDeque<>();
    private long buffered;
    private IOException failure;
    private boolean ended;
    private boolean aborted;
    private boolean resetByPeer;
    /** The tunnel's reader closed it, as a socket is closed: reads fail. */
    private boolean inputClosed;

    // The reading thread's.
    private final Http3StreamValidator rules;
    private final Http3Frames.State[] state = {Http3Frames.State.HEADERS};
    private boolean finalHead;
    private long declaredLength = -1;
    private long received;
    private boolean noContent;
    /** The request is a {@code CONNECT}: only DATA may follow its head. */
    private boolean connect;
    /** The request is an extended {@code CONNECT} ({@code :protocol}): its DATA are no message body. */
    private volatile boolean extendedConnect;
    /** How long reads of the body wait, in ms; 0 for ever, negative for the connection's idle timeout. */
    private volatile int readTimeoutMillis = -1;

    /** The exchange the stream carries, for the interceptor; null until it exists. */
    volatile FlowContext flow;
    /** The response answers a HEAD request: its content-length describes no content. */
    volatile boolean headRequest;

    private final Body body = new Body();

    Http3StreamReader(Http3Endpoint endpoint, QuicStream stream, boolean response, IntConsumer onBytes, Runnable onReset) {
        this.endpoint = endpoint;
        this.stream = stream;
        this.id = stream.id();
        this.response = response;
        this.onBytes = onBytes;
        this.onReset = onReset;
        this.rules = Http3StreamValidator.forRequestStream(id,
                response ? Http3StreamValidator.Role.CLIENT : Http3StreamValidator.Role.SERVER);
    }

    /** Starts reading on a virtual thread named {@code name}. */
    void start(String name) {
        Thread.ofVirtual().name(name).start(this::run);
    }

    // ---------------------------------------------------------------------------------------
    // Reading (the reader's thread)
    // ---------------------------------------------------------------------------------------

    private void run() {
        boolean clean = false;
        try {
            InputStream in = stream.getInputStream();
            if (onBytes != null) in = CountingStreams.counting(in, onBytes);
            Http3FrameReader reader = new Http3FrameReader(in);
            reader.setMaxFramePayloadSize(endpoint.maxFramePayload);
            for (io.github.mahmoudimus.http3.Http3Frame frame; (frame = reader.readFrame()) != null; ) {
                if (stopped()) return;
                rules.onFrame(frame);
                onFrame(frame);
            }
            rules.onEndOfStream();
            if (!noContent) Http3Headers.checkContentLength(id, declaredLength, received, true);
            clean = true;
            lock.lock();
            try {
                ended = true;
                events.addLast(new End());
                changed.signalAll();
            } finally {
                lock.unlock();
            }
        } catch (Http3Exception e) {
            if (e.isConnectionError()) {
                endpoint.connectionError(e.errorCode(), e.getMessage());
            } else {
                LOG.log(Level.DEBUG, endpoint.logPrefix + "stream " + id + ": " + e.getMessage());
                resetBothWays(e.errorCode());
            }
            fail(e);
        } catch (QuicStreamException e) {
            lock.lock();
            try {
                resetByPeer = !aborted;
            } finally {
                lock.unlock();
            }
            // Before the stream's exchange learns of the reset: it may then finish, and its stream
            // be forgotten, before the reset is seen as the client's.
            if (onReset != null) onReset.run();
            fail(e);
        } catch (QuicConnectionException e) {
            fail(e);
        } catch (IOException e) {
            if (!endpoint.closed) LOG.log(Level.DEBUG, endpoint.logPrefix + "stream " + id + " failed: " + e);
            fail(e);
        } catch (RuntimeException e) {
            LOG.log(Level.WARNING, endpoint.logPrefix + "unexpected error reading stream " + id, e);
            resetBothWays(Http3ErrorCode.H3_INTERNAL_ERROR);
            fail(new IOException("internal error", e));
        } finally {
            if (!clean) endpoint.cancelDecoding(id);
        }
    }

    private void onFrame(io.github.mahmoudimus.http3.Http3Frame frame) throws IOException {
        switch (frame) {
            case io.github.mahmoudimus.http3.Http3Frame.Headers h -> {
                List<HeaderField> fields;
                try {
                    fields = endpoint.decodeFields(id, h.fieldSection());
                } catch (FieldSectionSizeException e) {
                    if (finalHead || response) throw e;
                    // An oversized request head: the exchange answers 431, and reads no further.
                    finalHead = true;
                    queue(new Head(null), 0);
                    return;
                }
                if (response && !finalHead && interim(fields)) rules.interimResponse();
                if (endpoint.frames == null) {
                    onHeaders(fields);
                } else {
                    Http3Frame.Headers original = new Http3Frame.Headers(Http3Frames.fields(fields));
                    act(endpoint.frames.onStream(original, endpoint.receivedDirection(), endpoint.frameOrigin(), id, flow,
                            state, response));
                }
            }
            case io.github.mahmoudimus.http3.Http3Frame.Data d -> {
                if (d.data().length == 0) endpoint.count(Http3Endpoint.UNKNOWN_FRAME);
                if (endpoint.frames == null) {
                    onData(d.data());
                } else {
                    act(endpoint.frames.onStream(new Http3Frame.Data(d.data()), endpoint.receivedDirection(),
                            endpoint.frameOrigin(), id, flow, state, response));
                }
            }
            case io.github.mahmoudimus.http3.Http3Frame.Unknown u -> {
                // Ignored (RFC 9114 section 9), within the rate limit, once the interceptor has seen it.
                endpoint.count(Http3Endpoint.UNKNOWN_FRAME);
                if (endpoint.frames != null) {
                    act(endpoint.frames.onStream(new Http3Frame.Unknown(u.type(), u.payload()), endpoint.receivedDirection(),
                            endpoint.frameOrigin(), id, flow, state, response));
                }
            }
            case io.github.mahmoudimus.http3.Http3Frame.PushPromise p ->
                    // The proxy never sends MAX_PUSH_ID, so no push id is valid.
                    throw Http3Exception.connectionError(Http3ErrorCode.H3_ID_ERROR, "PUSH_PROMISE without MAX_PUSH_ID");
            default -> throw Http3Exception.connectionError(Http3ErrorCode.H3_FRAME_UNEXPECTED,
                    frame + " on request stream " + id);
        }
    }

    /** Acts on what the interceptor returned for a frame, as if the peer had sent it. */
    private void act(List<Http3Frame> acted) throws IOException {
        for (Http3Frame f : acted) {
            switch (f) {
                case Http3Frame.Headers h -> onHeaders(Http3Frames.codecFields(h.fields()));
                case Http3Frame.Data d -> onData(d.data());
                default -> {
                    // extension frames are ignored
                }
            }
        }
    }

    private static boolean interim(List<HeaderField> fields) {
        for (HeaderField f : fields) {
            if (f.name().equals(":status")) return f.value().length() == 3 && f.value().charAt(0) == '1';
        }
        return false;
    }

    private void onHeaders(List<HeaderField> fields) throws IOException {
        if (finalHead && connect) {
            throw Http3Exception.connectionError(Http3ErrorCode.H3_FRAME_UNEXPECTED, "HEADERS after CONNECT on stream " + id);
        }
        if (finalHead) {
            if (!noContent) Http3Headers.checkContentLength(id, declaredLength, received, true);
            queue(new Trailers(fields), 0);
            return;
        }
        boolean interimHead = response && interim(fields);
        if (!response) {
            for (HeaderField f : fields) {
                if (f.name().equals(":method")) connect = f.value().equals("CONNECT");
                if (f.name().equals(":protocol")) extendedConnect = true;
            }
        }
        if (!interimHead) {
            finalHead = true;
            declaredLength = contentLength(fields);
            noContent = response && (headRequest || status(fields) == 204 || status(fields) == 304);
        }
        queue(new Head(fields), 0);
    }

    private void onData(byte[] data) throws IOException {
        if (!finalHead) {
            throw Http3Exception.streamError(id, Http3ErrorCode.H3_FRAME_UNEXPECTED, "DATA before the header section");
        }
        received += data.length;
        if (!noContent) Http3Headers.checkContentLength(id, declaredLength, received, false);
        if (data.length > 0) queue(new Chunk(data), data.length);
    }

    private static long contentLength(List<HeaderField> fields) {
        for (HeaderField f : fields) {
            if (f.name().equals("content-length")) {
                try {
                    return Long.parseLong(f.value().strip());
                } catch (NumberFormatException e) {
                    return -1; // rejected with the head
                }
            }
        }
        return -1;
    }

    private static int status(List<HeaderField> fields) {
        for (HeaderField f : fields) {
            if (f.name().equals(":status")) {
                try {
                    return Integer.parseInt(f.value());
                } catch (NumberFormatException e) {
                    return 0;
                }
            }
        }
        return 0;
    }

    /** Queues an event, then waits while the body buffered is over {@link #BUFFER}. */
    private void queue(Object event, int size) throws IOException {
        lock.lock();
        try {
            if (aborted) throw new IOException("the stream's reading was stopped");
            events.addLast(event);
            buffered += size;
            changed.signalAll();
            while (buffered > BUFFER && !aborted && failure == null && !endpoint.closed) {
                changed.await();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new InterruptedIOException("interrupted reading stream " + id);
        } finally {
            lock.unlock();
        }
    }

    private boolean stopped() {
        lock.lock();
        try {
            return aborted;
        } finally {
            lock.unlock();
        }
    }

    private void fail(IOException e) {
        lock.lock();
        try {
            if (failure == null && !ended) failure = e;
            changed.signalAll();
        } finally {
            lock.unlock();
        }
    }

    private void resetBothWays(Http3ErrorCode code) {
        try {
            stream.stopSending(code.code());
        } catch (IOException | RuntimeException e) {
            // already finished
        }
        try {
            stream.reset(code.code());
        } catch (IOException | RuntimeException e) {
            // already finished or reset
        }
    }

    // ---------------------------------------------------------------------------------------
    // The exchange's side
    // ---------------------------------------------------------------------------------------

    /**
     * Waits up to {@code nanos} for the next header section; true when one has arrived, false on
     * timeout.
     *
     * @throws IOException if the stream failed, or ended without (another) header section
     */
    boolean awaitHead(long nanos) throws IOException {
        lock.lock();
        try {
            long remaining = nanos;
            while (true) {
                Object first = events.peekFirst();
                if (first instanceof Head) return true;
                if (first != null) throw new IOException("stream " + id + ": no header section where one was expected");
                if (failure != null) throw failure;
                if (endpoint.closed) throw new IOException("the HTTP/3 connection closed");
                if (remaining <= 0) return false;
                remaining = changed.awaitNanos(remaining);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new InterruptedIOException("interrupted waiting on stream " + id);
        } finally {
            lock.unlock();
        }
    }

    /** Takes the header section {@link #awaitHead} found; null if none is there. */
    Head takeHead() {
        lock.lock();
        try {
            return events.peekFirst() instanceof Head h ? (Head) events.pollFirst() : null;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Waits up to {@code nanos} for anything after what has been taken (data, trailers, the end of
     * the stream or a failure): HTTP/3 has no END_STREAM flag on HEADERS, so a peer that sends a
     * request without a body usually ends the stream in the packet that carries its HEADERS, and
     * this tells such a request from one whose body follows.
     */
    void awaitNext(long nanos) throws InterruptedIOException {
        lock.lock();
        try {
            long remaining = nanos;
            while (events.isEmpty() && failure == null && !endpoint.closed && remaining > 0) {
                remaining = changed.awaitNanos(remaining);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new InterruptedIOException("interrupted waiting on stream " + id);
        } finally {
            lock.unlock();
        }
    }

    /** Whether the stream ended right after what has been taken: a message with no body. */
    boolean endsHere() {
        lock.lock();
        try {
            return events.peekFirst() instanceof End;
        } finally {
            lock.unlock();
        }
    }

    /** Whether everything the peer sent has been read: the end of the stream, cleanly. */
    boolean ended() {
        lock.lock();
        try {
            return ended;
        } finally {
            lock.unlock();
        }
    }

    /** Whether the peer reset the stream. */
    boolean resetByPeer() {
        lock.lock();
        try {
            return resetByPeer;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Waits until {@link System#nanoTime()} reaches {@code deadline}, unless the stream fails
     * first; returns the failure, or null at the deadline.
     */
    IOException awaitFailure(long deadline) throws InterruptedIOException {
        lock.lock();
        try {
            long remaining;
            while (failure == null && !endpoint.closed && (remaining = deadline - System.nanoTime()) > 0) {
                changed.awaitNanos(remaining);
            }
            return failure != null ? failure : endpoint.closed ? new IOException("the HTTP/3 connection closed") : null;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new InterruptedIOException("interrupted while waiting");
        } finally {
            lock.unlock();
        }
    }

    /**
     * Stops reading the stream: the peer is asked to stop sending ({@code STOP_SENDING} with
     * {@code code}) unless it has sent everything, and what is queued is dropped.
     */
    void abort(Http3ErrorCode code) {
        boolean stop;
        lock.lock();
        try {
            if (aborted) return;
            aborted = true;
            stop = !ended && failure == null;
            events.clear();
            buffered = 0;
            changed.signalAll();
        } finally {
            lock.unlock();
        }
        if (stop) {
            try {
                stream.stopSending(code.code());
            } catch (IOException | RuntimeException e) {
                // finished meanwhile
            }
        }
    }

    /**
     * Sets how long reads of the body wait for the peer (a tunnel's, shown as a socket's read
     * timeout), in ms: 0 for ever; by default the connection's idle timeout.
     */
    void setReadTimeout(int millis) {
        readTimeoutMillis = Math.max(0, millis);
    }

    /** How long reads of the body wait, in ms, 0 for ever. */
    int readTimeout() {
        int millis = readTimeoutMillis;
        return millis >= 0 ? millis : Math.max(0, endpoint.server.idleTimeoutMillis());
    }

    /** Closes the body as a socket's input is closed: reads in progress and to come fail. */
    void closeInput() {
        lock.lock();
        try {
            inputClosed = true;
            changed.signalAll();
        } finally {
            lock.unlock();
        }
    }

    /** Fails the waits and reads with {@code cause}: the connection ended, or its GOAWAY left the stream unprocessed. */
    void failWith(IOException cause) {
        lock.lock();
        try {
            if (failure == null && !ended) failure = cause;
            changed.signalAll();
        } finally {
            lock.unlock();
        }
    }

    /** The message's body, as it arrives. */
    MessageBody body() {
        return body;
    }

    private final class Body implements MessageBody {
        private byte[] chunk;
        private int offset;
        private boolean done;
        private HttpHeaders trailers;

        @Override
        public boolean hasBody() {
            if (extendedConnect) return false;
            lock.lock();
            try {
                return !(events.peekFirst() instanceof End) && declaredLength != 0;
            } finally {
                lock.unlock();
            }
        }

        @Override
        public long declaredLength() {
            return declaredLength;
        }

        @Override
        public boolean isDone() {
            if (done) return true;
            lock.lock();
            try {
                return chunk == null && events.peekFirst() instanceof End;
            } finally {
                lock.unlock();
            }
        }

        @Override
        public HttpContent next() throws IOException {
            if (done) return null;
            if (chunk != null) {
                byte[] rest = Arrays.copyOfRange(chunk, offset, chunk.length);
                chunk = null;
                return new DefaultHttpContent(rest);
            }
            Object e = take();
            if (e instanceof Chunk c) return new DefaultHttpContent(c.data());
            done = true;
            HttpHeaders t = trailers;
            return t == null || t.isEmpty() ? LastHttpContent.empty() : new DefaultLastHttpContent(new byte[0], t);
        }

        @Override
        public int read(byte[] dst, int off, int len) throws IOException {
            if (done) return -1;
            if (chunk == null) {
                Object e = take();
                if (!(e instanceof Chunk c)) {
                    done = true;
                    return -1;
                }
                chunk = c.data();
                offset = 0;
            }
            int n = Math.min(len, chunk.length - offset);
            System.arraycopy(chunk, offset, dst, off, n);
            offset += n;
            if (offset == chunk.length) chunk = null;
            return n;
        }

        /** The next body event: a chunk, or the end (after which {@link #trailers} are known). */
        private Object take() throws IOException {
            int timeout = readTimeoutMillis;
            long remaining = timeout < 0 ? endpoint.readTimeoutNanos()
                    : timeout == 0 ? Long.MAX_VALUE : TimeUnit.MILLISECONDS.toNanos(timeout);
            lock.lock();
            try {
                while (true) {
                    if (inputClosed) throw new SocketException("stream " + id + " was closed");
                    Object first = events.peekFirst();
                    if (first instanceof Chunk c) {
                        events.pollFirst();
                        buffered -= c.data().length;
                        changed.signalAll();
                        return c;
                    }
                    if (first instanceof Trailers t) {
                        events.pollFirst();
                        HttpHeaders h = new HttpHeaders();
                        for (HeaderField f : Http3Headers.validateTrailers(id, t.fields())) h.add(f.name(), f.value());
                        trailers = h;
                        continue;
                    }
                    if (first instanceof End) return first;
                    if (first instanceof Head) throw new IOException("stream " + id + ": a header section inside the body");
                    if (failure != null) throw failure;
                    if (aborted) throw new IOException("stream " + id + " was closed");
                    if (endpoint.closed) throw new IOException("the HTTP/3 connection closed");
                    if (remaining <= 0) {
                        throw timeout < 0 ? endpoint.timedOut("data on stream " + id)
                                : new SocketTimeoutException("no data on stream " + id + " for " + timeout + " ms");
                    }
                    remaining = changed.awaitNanos(remaining);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new InterruptedIOException("interrupted reading stream " + id);
            } finally {
                lock.unlock();
            }
        }

        @Override
        public HttpHeaders trailers() {
            return trailers != null ? trailers : new HttpHeaders();
        }

        @Override
        public boolean hasBufferedInput() {
            if (chunk != null) return true;
            lock.lock();
            try {
                return events.peekFirst() instanceof Chunk;
            } finally {
                lock.unlock();
            }
        }
    }
}
