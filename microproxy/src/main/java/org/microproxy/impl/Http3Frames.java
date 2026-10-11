package org.microproxy.impl;

import io.github.mahmoudimus.http3.HeaderField;
import io.github.mahmoudimus.http3.Http3Exception;
import io.github.mahmoudimus.http3.Http3Settings;
import java.lang.System.Logger.Level;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.microproxy.FlowContext;
import org.microproxy.frames.Field;
import org.microproxy.frames.FrameContext;
import org.microproxy.frames.FrameDirection;
import org.microproxy.frames.FrameInterceptor;
import org.microproxy.frames.FrameProtocol;
import org.microproxy.frames.Http3Frame;
import org.microproxy.frames.HttpFrame;

/**
 * An {@link Http3Endpoint}'s side of the {@link FrameInterceptor}, as {@link Http2Frames} is an
 * HTTP/2 endpoint's: it runs the interceptor on the live frames of the endpoint's streams and
 * checks what comes back against the rules of {@link org.microproxy.frames.Http3FramePipeline}
 * (HTTP/3's version of {@link FrameInterceptor}'s), so that the endpoint gets frames it can act on
 * or send without breaking the protocol. Endpoints without an interceptor have none of this.
 *
 * <p>Field sections are converted as field lists: the endpoint decodes a received section through
 * QPACK before calling {@link #onStream} and encodes what comes back as it sends it, so QPACK
 * state never depends on what the interceptor does. A result that breaks a rule, or an
 * interceptor that throws, is logged and the original frame acted on instead.
 */
final class Http3Frames {

    private static final System.Logger LOG = System.getLogger(Http3Frames.class.getName());

    /** The largest extension frame payload accepted from an interceptor. */
    static final int MAX_PAYLOAD = 16_384;

    /** The settings HTTP/3 defines, which may only get stricter (received) or stay (sent). */
    private static final long[] DEFINED_SETTINGS = {
        Http3Frame.SETTINGS_QPACK_MAX_TABLE_CAPACITY, Http3Frame.SETTINGS_MAX_FIELD_SECTION_SIZE,
        Http3Frame.SETTINGS_QPACK_BLOCKED_STREAMS, Http3Frame.SETTINGS_ENABLE_CONNECT_PROTOCOL,
        Http3Frame.SETTINGS_H3_DATAGRAM
    };

    /** Where a message stands, as acted on: expecting its header section, in its body, or after its trailers. */
    enum State {
        HEADERS,
        BODY,
        DONE
    }

    /** Who a frame belongs to, for {@link FrameContext}. */
    record Origin(long connectionId, InetSocketAddress clientAddress, String server) {}

    private final FrameInterceptor interceptor;
    private final ProtocolStats.HookStats stats;

    /** @param stats counts the interceptor's calls */
    Http3Frames(FrameInterceptor interceptor, ProtocolStats.HookStats stats) {
        this.interceptor = Objects.requireNonNull(interceptor);
        this.stats = stats;
    }

    // ---------------------------------------------------------------------------------------
    // Conversion
    // ---------------------------------------------------------------------------------------

    static List<Field> fields(List<HeaderField> fields) {
        List<Field> out = new ArrayList<>(fields.size());
        for (HeaderField f : fields) out.add(new Field(f.name(), f.value(), f.sensitive()));
        return out;
    }

    static List<HeaderField> codecFields(List<Field> fields) {
        List<HeaderField> out = new ArrayList<>(fields.size());
        for (Field f : fields) out.add(new HeaderField(f.name(), f.value(), f.sensitive()));
        return out;
    }

    /** A frame of a control stream, which carries no field section. */
    static Http3Frame toPublic(io.github.mahmoudimus.http3.Http3Frame frame) {
        return switch (frame) {
            case io.github.mahmoudimus.http3.Http3Frame.Data d -> new Http3Frame.Data(d.data());
            case io.github.mahmoudimus.http3.Http3Frame.Settings s -> new Http3Frame.Settings(s.values());
            case io.github.mahmoudimus.http3.Http3Frame.GoAway g -> new Http3Frame.GoAway(g.id());
            case io.github.mahmoudimus.http3.Http3Frame.CancelPush c -> new Http3Frame.CancelPush(c.pushId());
            case io.github.mahmoudimus.http3.Http3Frame.MaxPushId m -> new Http3Frame.MaxPushId(m.pushId());
            case io.github.mahmoudimus.http3.Http3Frame.Unknown u -> new Http3Frame.Unknown(u.type(), u.payload());
            case io.github.mahmoudimus.http3.Http3Frame.Headers h -> throw new IllegalArgumentException("HEADERS need their decoded fields");
            case io.github.mahmoudimus.http3.Http3Frame.PushPromise p ->
                    throw new IllegalArgumentException("PUSH_PROMISE needs its decoded fields");
        };
    }

    // ---------------------------------------------------------------------------------------
    // Interception
    // ---------------------------------------------------------------------------------------

    /**
     * Shows a frame of a request stream (a request, or the response to it) to the interceptor, and
     * returns what to act on in its place: what the interceptor returned and added, if it follows
     * the rules, else the frame itself.
     *
     * @param state where the message stands as acted on; moved on past what is returned
     * @param response whether the frames are a response's, whose interim (1xx) header sections
     *     come before the final one
     */
    List<Http3Frame> onStream(Http3Frame frame, FrameDirection direction, Origin origin, long streamId, FlowContext flow,
            State[] state, boolean response) throws Http3Exception {
        List<HttpFrame> emitted = intercept(frame, direction, origin, streamId, flow);
        if (emitted != null) {
            String problem = checkStream(frame, emitted, state, response);
            if (problem == null) return http3(emitted);
            rejected(frame, streamId, problem);
        }
        State[] copy = {state[0]};
        String problem = advance(copy, frame, response);
        if (problem != null) {
            throw Http3Exception.streamError(streamId, io.github.mahmoudimus.http3.Http3ErrorCode.H3_FRAME_UNEXPECTED,
                    "stream " + streamId + ": " + problem + ", after a frame interceptor ended the message");
        }
        state[0] = copy[0];
        return List.of(frame);
    }

    /**
     * Shows a frame of a control stream to the interceptor: SETTINGS received may only become
     * stricter, SETTINGS sent may change only in extension settings, GOAWAY, MAX_PUSH_ID and
     * CANCEL_PUSH are read-only, and extension frames may be edited, dropped or added.
     */
    List<Http3Frame> onControl(Http3Frame frame, FrameDirection direction, Origin origin, long streamId) {
        List<HttpFrame> emitted = intercept(frame, direction, origin, streamId, null);
        if (emitted == null) return List.of(frame);
        String problem = checkControl(frame, emitted, direction.inbound());
        if (problem == null) return http3(emitted);
        rejected(frame, streamId, problem);
        return List.of(frame);
    }

    /** What the interceptor returned and added, in order; null if it threw. */
    private List<HttpFrame> intercept(Http3Frame frame, FrameDirection direction, Origin origin, long streamId, FlowContext flow) {
        Context ctx = new Context(origin, streamId, flow);
        HttpFrame result;
        long start = stats.start();
        try {
            result = interceptor.intercept(frame, direction, ctx);
            stats.end(start);
            stats.outcome(frame, ctx.sent.isEmpty() || result == null ? result : ctx);
        } catch (RuntimeException e) {
            stats.failed(start);
            LOG.log(Level.WARNING, "frame interceptor failed on HTTP/3 " + frame.typeName() + " on stream " + streamId
                    + "; passing the frame on unchanged", e);
            return null;
        } finally {
            ctx.done = true;
        }
        List<HttpFrame> emitted = new ArrayList<>(1 + ctx.sent.size());
        if (result != null) emitted.add(result);
        emitted.addAll(ctx.sent);
        return emitted;
    }

    private static void rejected(Http3Frame frame, long streamId, String problem) {
        LOG.log(Level.WARNING, "frame interceptor result rejected for HTTP/3 " + frame.typeName() + " on stream " + streamId
                + ": " + problem + "; passing the frame on unchanged");
    }

    private static List<Http3Frame> http3(List<HttpFrame> emitted) {
        List<Http3Frame> out = new ArrayList<>(emitted.size());
        for (HttpFrame f : emitted) out.add((Http3Frame) f);
        return out;
    }

    private static boolean interim(Http3Frame.Headers h) {
        String status = h.get(":status");
        return status != null && status.length() == 3 && status.charAt(0) == '1';
    }

    /** Moves the message's state past {@code f}; why it cannot follow, or null. */
    private static String advance(State[] state, Http3Frame f, boolean response) {
        switch (f) {
            case Http3Frame.Data d -> {
                if (state[0] != State.BODY) return "DATA " + (state[0] == State.HEADERS ? "before HEADERS" : "after trailers");
            }
            case Http3Frame.Headers h -> {
                switch (state[0]) {
                    case HEADERS -> state[0] = response && interim(h) ? State.HEADERS : State.BODY;
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

    /** Why the result for a request stream's {@code original} cannot be acted on, or null; moves {@code state} on if it can. */
    private static String checkStream(Http3Frame original, List<HttpFrame> emitted, State[] state, boolean response) {
        List<Http3Frame> out = new ArrayList<>(emitted.size());
        for (HttpFrame f : emitted) {
            if (!(f instanceof Http3Frame h3)) return "not an HTTP/3 frame: " + f;
            out.add(h3);
        }
        boolean droppable = original instanceof Http3Frame.Data || original instanceof Http3Frame.Unknown;
        if (!droppable) {
            if (out.isEmpty()) return original.typeName() + " cannot be dropped";
            if (out.getFirst().getClass() != original.getClass()) {
                return original.typeName() + " can only be replaced by " + original.typeName() + ", not " + out.getFirst().typeName();
            }
        }
        State[] next = {state[0]};
        for (Http3Frame f : out) {
            if (f instanceof Http3Frame.Unknown u) {
                String problem = unknownProblem(u);
                if (problem != null) return problem;
                continue;
            }
            String problem = switch (original) {
                case Http3Frame.Data d -> f instanceof Http3Frame.Data || f instanceof Http3Frame.Headers ? null
                        : f.typeName() + " in place of DATA";
                case Http3Frame.Headers h -> f instanceof Http3Frame.Headers ? null : f.typeName() + " in place of HEADERS";
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
            problem = advance(next, f, response);
            if (problem != null) return problem;
        }
        state[0] = next[0];
        return null;
    }

    /** Why an extension frame cannot be sent or acted on (its record already checked its type), or null. */
    private static String unknownProblem(Http3Frame.Unknown u) {
        return u.payload().length > MAX_PAYLOAD ? "extension frame payload of " + u.payload().length + " bytes" : null;
    }

    /** Why the result for a control stream's {@code original} cannot be acted on, or null. */
    private static String checkControl(Http3Frame original, List<HttpFrame> emitted, boolean received) {
        List<Http3Frame> out = new ArrayList<>(emitted.size());
        for (HttpFrame f : emitted) {
            if (!(f instanceof Http3Frame h3)) return "not an HTTP/3 frame: " + f;
            out.add(h3);
        }
        boolean readOnly = original instanceof Http3Frame.GoAway || original instanceof Http3Frame.MaxPushId
                || original instanceof Http3Frame.CancelPush;
        boolean droppable = original instanceof Http3Frame.Unknown;
        if (!droppable) {
            if (out.isEmpty()) return original.typeName() + " cannot be dropped";
            if (out.getFirst().getClass() != original.getClass()) {
                return original.typeName() + " can only be replaced by " + original.typeName() + ", not " + out.getFirst().typeName();
            }
            if (readOnly && !out.getFirst().equals(original)) return original.typeName() + " is read-only";
        }
        for (int i = droppable ? 0 : 1; i < out.size(); i++) {
            if (!(out.get(i) instanceof Http3Frame.Unknown u)) {
                return "only extension frames may follow " + original.typeName() + ", not " + out.get(i).typeName();
            }
            String problem = unknownProblem(u);
            if (problem != null) return problem;
        }
        if (original instanceof Http3Frame.Settings before && out.getFirst() instanceof Http3Frame.Settings after) {
            return received ? stricter(before, after) : sameDefinedSettings(before, after);
        }
        return null;
    }

    /** Why {@code after}, received in place of {@code before}, would make the proxy less strict; null if it does not. */
    private static String stricter(Http3Frame.Settings before, Http3Frame.Settings after) {
        for (Map.Entry<Long, Long> e : after.values().entrySet()) {
            try {
                Http3Settings.validate(e.getKey(), e.getValue());
            } catch (Http3Exception ex) {
                return "invalid SETTINGS: " + ex.getMessage();
            }
        }
        for (long id : DEFINED_SETTINGS) {
            long was = settingOrDefault(before, id);
            long now = settingOrDefault(after, id);
            if (now > was) {
                return "SETTINGS_" + Http3Frame.settingName(id) + " " + now + " is less strict than " + was;
            }
        }
        return null;
    }

    /** Why {@code after}, sent in place of {@code before}, changes a setting the proxy relies on; null if it does not. */
    private static String sameDefinedSettings(Http3Frame.Settings before, Http3Frame.Settings after) {
        for (Map.Entry<Long, Long> e : after.values().entrySet()) {
            try {
                Http3Settings.validate(e.getKey(), e.getValue());
            } catch (Http3Exception ex) {
                return "invalid SETTINGS: " + ex.getMessage();
            }
        }
        for (long id : DEFINED_SETTINGS) {
            if (!Objects.equals(before.get(id), after.get(id))) {
                return "SETTINGS_" + Http3Frame.settingName(id) + " is the proxy's own";
            }
        }
        return null;
    }

    /** A setting's value, or what its absence means (RFC 9114 section 7.2.4.1, RFC 9204 section 5). */
    static long settingOrDefault(Http3Frame.Settings settings, long id) {
        Long v = settings.get(id);
        if (v != null) return v;
        return id == Http3Frame.SETTINGS_MAX_FIELD_SECTION_SIZE ? Long.MAX_VALUE : 0;
    }

    /** One interceptor call's {@link FrameContext}. */
    private static final class Context implements FrameContext {
        private final Origin origin;
        private final long streamId;
        private final FlowContext flow;
        final List<HttpFrame> sent = new ArrayList<>(0);
        volatile boolean done;

        Context(Origin origin, long streamId, FlowContext flow) {
            this.origin = origin;
            this.streamId = streamId;
            this.flow = flow;
        }

        @Override
        public FrameProtocol protocol() {
            return FrameProtocol.HTTP_3;
        }

        @Override
        public long connectionId() {
            return flow != null ? flow.getConnectionId() : origin.connectionId();
        }

        @Override
        public InetSocketAddress clientAddress() {
            return flow != null ? flow.getClientAddress() : origin.clientAddress();
        }

        @Override
        public String server() {
            return origin.server();
        }

        @Override
        public long streamId() {
            return streamId;
        }

        @Override
        public FlowContext flowContext() {
            return flow;
        }

        @Override
        public void send(HttpFrame frame) {
            Objects.requireNonNull(frame, "frame");
            if (done) throw new IllegalStateException("the interceptor call this context belongs to has returned");
            sent.add(frame);
        }

        @Override
        public String toString() {
            return "FrameContext[h3, connection " + connectionId() + ", stream " + streamId + "]";
        }
    }
}
