package org.microproxy.frames;

import io.github.mahmoudimus.http3.HeaderField;
import io.github.mahmoudimus.http3.Http3ErrorCode;
import io.github.mahmoudimus.http3.Http3Exception;
import io.github.mahmoudimus.http3.Http3FrameReader;
import io.github.mahmoudimus.http3.Http3FrameWriter;
import io.github.mahmoudimus.http3.Http3Settings;
import io.github.mahmoudimus.http3.Http3StreamType;
import io.github.mahmoudimus.http3.Http3StreamValidator;
import io.github.mahmoudimus.http3.QpackDecoder;
import io.github.mahmoudimus.http3.QpackEncoder;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.System.Logger.Level;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.locks.ReentrantLock;
import org.microproxy.FlowContext;

/**
 * The codec side of {@link Http3FramePipeline}: reading, decoding, interception, checks and
 * writing. A class of its own, loaded only once a pipeline is built, so that nothing touches the
 * optional {@code http3-codec} module before {@link Http3FramePipeline#available()} said it is
 * there.
 */
final class Http3Streams {

    private static final System.Logger LOG = System.getLogger(Http3FramePipeline.class.getName());

    /** Where a message stands, as written: expecting a header section, in the body, or after trailers. */
    private enum State {
        HEADERS,
        BODY,
        DONE
    }

    private final FrameInterceptor interceptor;
    private final FrameDirection direction;
    private final long connectionId;
    private final InetSocketAddress clientAddress;
    private final String server;
    private final int maxFramePayloadSize;
    /** The frames are a client's (requests) rather than a server's (responses). */
    private final boolean fromClient;

    /** Guards {@link #decoder}, which the sender's request streams and its encoder stream share. */
    private final ReentrantLock qpackLock = new ReentrantLock();
    private final QpackDecoder decoder;

    Http3Streams(FrameInterceptor interceptor, FrameDirection direction, long connectionId, InetSocketAddress clientAddress,
            String server, long qpackMaxTableCapacity, int qpackBlockedStreams, int maxFramePayloadSize,
            long maxFieldSectionSize) {
        this.interceptor = interceptor;
        this.direction = direction;
        this.connectionId = connectionId;
        this.clientAddress = clientAddress;
        this.server = server;
        this.maxFramePayloadSize = maxFramePayloadSize;
        this.fromClient = direction == FrameDirection.FROM_CLIENT || direction == FrameDirection.TO_SERVER;
        this.decoder = new QpackDecoder(qpackMaxTableCapacity, qpackBlockedStreams);
        decoder.setMaxFieldSectionSize(maxFieldSectionSize);
    }

    /** The validators' role: the endpoint that receives these frames. */
    private Http3StreamValidator.Role receiver() {
        return fromClient ? Http3StreamValidator.Role.SERVER : Http3StreamValidator.Role.CLIENT;
    }

    // ---------------------------------------------------------------------------------------
    // Streams
    // ---------------------------------------------------------------------------------------

    void requestStream(long streamId, InputStream in, OutputStream out) throws IOException {
        Http3FrameReader reader = new Http3FrameReader(in);
        reader.setMaxFramePayloadSize(maxFramePayloadSize);
        Http3FrameWriter writer = new Http3FrameWriter(out);
        Http3StreamValidator rules = Http3StreamValidator.forRequestStream(streamId, receiver());
        QpackEncoder encoder = new QpackEncoder();
        State[] state = {State.HEADERS};
        try {
            for (io.github.mahmoudimus.http3.Http3Frame frame; (frame = reader.readFrame()) != null; ) {
                rules.onFrame(frame);
                Http3Frame original = toPublic(frame, streamId);
                if (!fromClient && original instanceof Http3Frame.Headers h && interim(h)) interimResponse(rules, streamId);
                for (Http3Frame f : intercept(original, streamId, state)) write(writer, encoder, streamId, f);
                writer.flush();
            }
            rules.onEndOfStream();
        } catch (IOException | RuntimeException e) {
            cancel(streamId);
            throw e;
        }
    }

    void controlStream(long streamId, InputStream in, OutputStream out) throws IOException {
        Http3FrameReader reader = new Http3FrameReader(in);
        reader.setMaxFramePayloadSize(maxFramePayloadSize);
        long type = reader.readStreamType();
        if (type < 0) return;
        if (type != Http3StreamType.CONTROL) {
            throw Http3Exception.connectionError(Http3ErrorCode.H3_STREAM_CREATION_ERROR,
                    "not a control stream: stream type " + Http3StreamType.name(type));
        }
        Http3FrameWriter writer = new Http3FrameWriter(out);
        writer.writeStreamType(Http3StreamType.CONTROL);
        writer.flush();
        Http3StreamValidator rules = Http3StreamValidator.forControlStream(receiver());
        // The end of the input is where the capture ends: a live control stream never ends.
        for (io.github.mahmoudimus.http3.Http3Frame frame; (frame = reader.readFrame()) != null; ) {
            rules.onFrame(frame);
            for (Http3Frame f : intercept(toPublic(frame, streamId), streamId, null)) write(writer, null, streamId, f);
            writer.flush();
        }
    }

    void encoderStream(InputStream in) throws IOException {
        long type = Http3StreamType.read(in);
        if (type < 0) return;
        if (type != Http3StreamType.QPACK_ENCODER) {
            throw Http3Exception.connectionError(Http3ErrorCode.H3_STREAM_CREATION_ERROR,
                    "not a QPACK encoder stream: stream type " + Http3StreamType.name(type));
        }
        byte[] buffer = new byte[4096];
        for (int n; (n = in.read(buffer)) >= 0; ) {
            qpackLock.lock();
            try {
                decoder.onEncoderStream(buffer, 0, n);
            } finally {
                qpackLock.unlock();
            }
        }
    }

    private void cancel(long streamId) {
        qpackLock.lock();
        try {
            decoder.cancelStream(streamId);
        } finally {
            qpackLock.unlock();
        }
    }

    private static void interimResponse(Http3StreamValidator rules, long streamId) throws Http3Exception {
        try {
            rules.interimResponse();
        } catch (IllegalStateException e) {
            throw Http3Exception.connectionError(Http3ErrorCode.H3_FRAME_UNEXPECTED,
                    "an interim response after the response's header section on stream " + streamId);
        }
    }

    private static boolean interim(Http3Frame.Headers h) {
        String status = h.get(":status");
        return status != null && status.length() == 3 && status.charAt(0) == '1';
    }

    // ---------------------------------------------------------------------------------------
    // Conversion
    // ---------------------------------------------------------------------------------------

    private Http3Frame toPublic(io.github.mahmoudimus.http3.Http3Frame frame, long streamId) throws IOException {
        return switch (frame) {
            case io.github.mahmoudimus.http3.Http3Frame.Data d -> new Http3Frame.Data(d.data());
            case io.github.mahmoudimus.http3.Http3Frame.Headers h -> new Http3Frame.Headers(decode(streamId, h.fieldSection()));
            case io.github.mahmoudimus.http3.Http3Frame.PushPromise p ->
                    new Http3Frame.PushPromise(p.pushId(), decode(streamId, p.fieldSection()));
            case io.github.mahmoudimus.http3.Http3Frame.Settings s -> new Http3Frame.Settings(s.values());
            case io.github.mahmoudimus.http3.Http3Frame.GoAway g -> new Http3Frame.GoAway(g.id());
            case io.github.mahmoudimus.http3.Http3Frame.CancelPush c -> new Http3Frame.CancelPush(c.pushId());
            case io.github.mahmoudimus.http3.Http3Frame.MaxPushId m -> new Http3Frame.MaxPushId(m.pushId());
            case io.github.mahmoudimus.http3.Http3Frame.Unknown u -> new Http3Frame.Unknown(u.type(), u.payload());
        };
    }

    private List<Field> decode(long streamId, byte[] section) throws IOException {
        List<HeaderField> fields;
        qpackLock.lock();
        try {
            fields = decoder.decode(streamId, section);
            if (fields == null) {
                decoder.cancelStream(streamId);
                throw new IOException("the field section on stream " + streamId
                        + " needs QPACK encoder stream instructions not given yet (Http3FramePipeline.encoderStream)");
            }
        } finally {
            qpackLock.unlock();
        }
        List<Field> out = new ArrayList<>(fields.size());
        for (HeaderField f : fields) out.add(new Field(f.name(), f.value(), f.sensitive()));
        return out;
    }

    private static List<HeaderField> codecFields(List<Field> fields) {
        List<HeaderField> out = new ArrayList<>(fields.size());
        for (Field f : fields) out.add(new HeaderField(f.name(), f.value(), f.sensitive()));
        return out;
    }

    /** Writes one frame; field sections are encoded with static-only QPACK. */
    private static void write(Http3FrameWriter writer, QpackEncoder encoder, long streamId, Http3Frame frame) throws IOException {
        switch (frame) {
            case Http3Frame.Data d -> writer.writeData(d.data());
            case Http3Frame.Headers h -> writer.writeHeaders(encoder.encode(streamId, codecFields(h.fields())));
            case Http3Frame.PushPromise p -> writer.writePushPromise(p.pushId(), encoder.encode(streamId, codecFields(p.fields())));
            case Http3Frame.Settings s -> writer.writeFrame(new io.github.mahmoudimus.http3.Http3Frame.Settings(s.values()));
            case Http3Frame.GoAway g -> writer.writeGoAway(g.id());
            case Http3Frame.CancelPush c -> writer.writeCancelPush(c.pushId());
            case Http3Frame.MaxPushId m -> writer.writeMaxPushId(m.pushId());
            case Http3Frame.Unknown u -> writer.writeFrame(new io.github.mahmoudimus.http3.Http3Frame.Unknown(u.type(), u.payload()));
        }
    }

    // ---------------------------------------------------------------------------------------
    // Interception
    // ---------------------------------------------------------------------------------------

    /**
     * What to write for {@code frame}: what the interceptor returned and added, if it follows the
     * rules, else the frame itself. {@code state} is where the message stands as written (null on
     * the control stream), moved on past what is returned.
     */
    private List<Http3Frame> intercept(Http3Frame frame, long streamId, State[] state) throws Http3Exception {
        Context ctx = new Context(streamId);
        HttpFrame result;
        try {
            result = interceptor.intercept(frame, direction, ctx);
        } catch (RuntimeException e) {
            LOG.log(Level.WARNING, "frame interceptor failed on HTTP/3 " + frame.typeName() + " on stream " + streamId
                    + "; passing the frame on unchanged", e);
            return original(frame, streamId, state);
        } finally {
            ctx.done = true;
        }
        List<HttpFrame> emitted = new ArrayList<>(1 + ctx.sent.size());
        if (result != null) emitted.add(result);
        emitted.addAll(ctx.sent);
        String problem = check(frame, emitted, state);
        if (problem != null) {
            LOG.log(Level.WARNING, "frame interceptor result rejected for HTTP/3 " + frame.typeName() + " on stream " + streamId
                    + ": " + problem + "; passing the frame on unchanged");
            return original(frame, streamId, state);
        }
        List<Http3Frame> out = new ArrayList<>(emitted.size());
        for (HttpFrame f : emitted) out.add((Http3Frame) f);
        return out;
    }

    /** The frame alone, if it still fits what was written. */
    private List<Http3Frame> original(Http3Frame frame, long streamId, State[] state) throws Http3Exception {
        if (state != null) {
            State[] copy = {state[0]};
            String problem = advance(copy, frame);
            if (problem != null) {
                throw Http3Exception.connectionError(Http3ErrorCode.H3_FRAME_UNEXPECTED, "stream " + streamId + ": " + problem
                        + ", after a frame interceptor ended the message");
            }
            state[0] = copy[0];
        }
        return List.of(frame);
    }

    /** Moves the written message's state past {@code f}; why it cannot follow, or null. */
    private String advance(State[] state, Http3Frame f) {
        switch (f) {
            case Http3Frame.Data d -> {
                if (state[0] != State.BODY) return "DATA " + (state[0] == State.HEADERS ? "before HEADERS" : "after trailers");
            }
            case Http3Frame.Headers h -> {
                switch (state[0]) {
                    case HEADERS -> state[0] = !fromClient && interim(h) ? State.HEADERS : State.BODY;
                    case BODY -> state[0] = State.DONE;
                    case DONE -> {
                        return "HEADERS after trailers";
                    }
                }
            }
            default -> {}
        }
        return null;
    }

    /** Why the result for {@code original} cannot be written, or null; moves {@code state} on if it can. */
    private String check(Http3Frame original, List<HttpFrame> emitted, State[] state) {
        List<Http3Frame> out = new ArrayList<>(emitted.size());
        for (HttpFrame f : emitted) {
            if (!(f instanceof Http3Frame h3)) return "not an HTTP/3 frame: " + f;
            out.add(h3);
        }
        boolean readOnly = original instanceof Http3Frame.GoAway || original instanceof Http3Frame.MaxPushId
                || original instanceof Http3Frame.CancelPush || original instanceof Http3Frame.PushPromise;
        if (readOnly) {
            return out.size() == 1 && out.getFirst().equals(original) ? null : original.typeName() + " is read-only";
        }
        boolean droppable = original instanceof Http3Frame.Data || original instanceof Http3Frame.Unknown;
        if (!droppable) {
            if (out.isEmpty()) return original.typeName() + " cannot be dropped";
            if (out.getFirst().getClass() != original.getClass()) {
                return original.typeName() + " can only be replaced by " + original.typeName() + ", not " + out.getFirst().typeName();
            }
        }
        State[] next = state == null ? null : new State[] {state[0]};
        for (int i = 0; i < out.size(); i++) {
            Http3Frame f = out.get(i);
            if (f instanceof Http3Frame.Unknown) continue;
            String problem = switch (original) {
                case Http3Frame.Data d -> f instanceof Http3Frame.Data || f instanceof Http3Frame.Headers ? null
                        : f.typeName() + " in place of DATA";
                case Http3Frame.Headers h -> f instanceof Http3Frame.Headers ? null : f.typeName() + " in place of HEADERS";
                case Http3Frame.Settings s -> i > 0 ? "a second " + f.typeName() : settingsProblem((Http3Frame.Settings) f);
                default -> f.typeName() + " in place of " + original.typeName();
            };
            if (problem != null) return problem;
            if (f instanceof Http3Frame.Headers h) {
                try {
                    Field.validate(h.fields());
                } catch (IllegalArgumentException e) {
                    return "invalid field section: " + e.getMessage();
                }
            }
            if (next != null) {
                problem = advance(next, f);
                if (problem != null) return problem;
            }
        }
        if (next != null) state[0] = next[0];
        return null;
    }

    private static String settingsProblem(Http3Frame.Settings settings) {
        for (Map.Entry<Long, Long> e : settings.values().entrySet()) {
            try {
                Http3Settings.validate(e.getKey(), e.getValue());
            } catch (Http3Exception ex) {
                return "invalid SETTINGS: " + ex.getMessage();
            }
        }
        return null;
    }

    /** One interceptor call's {@link FrameContext}. */
    private final class Context implements FrameContext {
        private final long streamId;
        final List<HttpFrame> sent = new ArrayList<>(0);
        volatile boolean done;

        Context(long streamId) {
            this.streamId = streamId;
        }

        @Override
        public FrameProtocol protocol() {
            return FrameProtocol.HTTP_3;
        }

        @Override
        public long connectionId() {
            return connectionId;
        }

        @Override
        public InetSocketAddress clientAddress() {
            return clientAddress;
        }

        @Override
        public String server() {
            return server;
        }

        @Override
        public long streamId() {
            return streamId;
        }

        @Override
        public FlowContext flowContext() {
            return null;
        }

        @Override
        public void send(HttpFrame frame) {
            Objects.requireNonNull(frame, "frame");
            if (done) throw new IllegalStateException("the interceptor call this context belongs to has returned");
            sent.add(frame);
        }

        @Override
        public String toString() {
            return "FrameContext[h3, connection " + connectionId + ", stream " + streamId + "]";
        }
    }
}
