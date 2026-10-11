package org.microproxy.impl;

import io.github.mahmoudimus.http2.Frame;
import io.github.mahmoudimus.http2.HeaderField;
import java.lang.System.Logger.Level;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import org.microproxy.FlowContext;
import org.microproxy.frames.Field;
import org.microproxy.frames.FrameContext;
import org.microproxy.frames.FrameDirection;
import org.microproxy.frames.FrameInterceptor;
import org.microproxy.frames.FrameProtocol;
import org.microproxy.frames.Http2Frame;
import org.microproxy.frames.HttpFrame;

/**
 * An {@link Http2Endpoint}'s side of the {@link FrameInterceptor}: it converts between the codec's
 * frames and the public {@link Http2Frame}s, runs the interceptor, and checks what it returns
 * against the rules {@link FrameInterceptor} documents, so the endpoint gets frames it can act on
 * or send without breaking the protocol. Endpoints without an interceptor have none of this (their
 * {@code frames} is null), so frames cost nothing extra there.
 *
 * <p>Header blocks are converted as field lists: the endpoint decodes a received block before
 * calling {@link #intercept} and encodes what comes back as it sends it, so HPACK state never
 * depends on what the interceptor does.
 */
final class Http2Frames {

    private static final System.Logger LOG = System.getLogger(Http2Frames.class.getName());

    /** The largest extension frame payload or GOAWAY debug data accepted: what any peer can take. */
    static final int MAX_PAYLOAD = 16_384 - 8;

    /** The settings whose values the proxy relies on, which its own SETTINGS keep. */
    private static final int[] DEFINED_SETTINGS = {
        Http2Frame.SETTINGS_HEADER_TABLE_SIZE, Http2Frame.SETTINGS_ENABLE_PUSH, Http2Frame.SETTINGS_MAX_CONCURRENT_STREAMS,
        Http2Frame.SETTINGS_INITIAL_WINDOW_SIZE, Http2Frame.SETTINGS_MAX_FRAME_SIZE, Http2Frame.SETTINGS_MAX_HEADER_LIST_SIZE,
        Http2Frame.SETTINGS_ENABLE_CONNECT_PROTOCOL
    };

    private final FrameInterceptor interceptor;
    private final Http2Endpoint endpoint;

    Http2Frames(FrameInterceptor interceptor, Http2Endpoint endpoint) {
        this.interceptor = interceptor;
        this.endpoint = endpoint;
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

    /** A received frame other than HEADERS, PUSH_PROMISE and CONTINUATION (which carry header blocks). */
    static Http2Frame toPublic(Frame frame) {
        return switch (frame) {
            case Frame.Data d -> new Http2Frame.Data(d.streamId(), d.data(), d.endStream());
            case Frame.Priority p -> new Http2Frame.Priority(p.streamId(), p.spec().streamDependency(), p.spec().exclusive(),
                    p.spec().weight());
            case Frame.RstStream r -> new Http2Frame.RstStream(r.streamId(), r.errorCode() & 0xffffffffL);
            case Frame.Settings s -> new Http2Frame.Settings(s.ack(), s.values());
            case Frame.Ping p -> new Http2Frame.Ping(p.ack(), p.opaqueData());
            case Frame.GoAway g -> new Http2Frame.GoAway(g.lastStreamId(), g.errorCode() & 0xffffffffL, g.debugData());
            case Frame.WindowUpdate w -> new Http2Frame.WindowUpdate(w.streamId(), w.increment());
            case Frame.Unknown u -> new Http2Frame.Unknown(u.type(), u.flags(), u.streamId(), u.payload());
            case Frame.Headers h -> throw new IllegalArgumentException("HEADERS need their decoded fields");
            case Frame.PushPromise p -> throw new IllegalArgumentException("PUSH_PROMISE is not intercepted");
            case Frame.Continuation c -> throw new IllegalArgumentException("CONTINUATION is folded into HEADERS");
        };
    }

    /** A frame to send or act on, other than HEADERS (which the endpoint encodes) and PUSH_PROMISE. */
    static Frame toCodec(Http2Frame frame) {
        return switch (frame) {
            case Http2Frame.Data d -> new Frame.Data(d.streamId(), d.data(), d.endStream());
            case Http2Frame.Priority p -> new Frame.Priority(p.streamId(),
                    new Frame.PrioritySpec(p.streamDependency(), p.exclusive(), p.weight()));
            case Http2Frame.RstStream r -> new Frame.RstStream(r.streamId(), (int) r.errorCode());
            case Http2Frame.Settings s -> new Frame.Settings(s.ack(), s.values());
            case Http2Frame.Ping p -> new Frame.Ping(p.ack(), p.opaqueData());
            case Http2Frame.GoAway g -> new Frame.GoAway(g.lastStreamId(), (int) g.errorCode(), g.debugData());
            case Http2Frame.WindowUpdate w -> new Frame.WindowUpdate(w.streamId(), w.increment());
            case Http2Frame.Unknown u -> new Frame.Unknown(u.type(), u.flags(), u.streamId(), u.payload());
            case Http2Frame.Headers h -> throw new IllegalArgumentException("HEADERS are encoded by the endpoint");
            case Http2Frame.PushPromise p -> throw new IllegalArgumentException("PUSH_PROMISE is never sent");
        };
    }

    // ---------------------------------------------------------------------------------------
    // Interception
    // ---------------------------------------------------------------------------------------

    /**
     * Shows {@code frame} to the interceptor and returns what to act on or send in its place, in
     * order: what the interceptor returned and added, checked and with END_STREAM where it belongs;
     * or {@code frame} alone if the interceptor failed or broke a rule (which is logged). Called
     * with no lock held, except for the HEADERS that open a stream to a server (under writeLock).
     *
     * @param flow the exchange the frame belongs to, or null
     */
    List<Http2Frame> intercept(Http2Frame frame, FrameDirection direction, FlowContext flow) {
        Context ctx = new Context(frame.streamId(), flow);
        HttpFrame result;
        try {
            result = interceptor.intercept(frame, direction, ctx);
        } catch (RuntimeException e) {
            LOG.log(Level.WARNING, endpoint.logPrefix + "frame interceptor failed on " + describe(frame, direction)
                    + "; passing the frame on unchanged", e);
            return List.of(frame);
        } finally {
            ctx.done = true;
        }
        if (result == frame && ctx.sent.isEmpty()) return List.of(frame);
        List<HttpFrame> emitted = new ArrayList<>(1 + ctx.sent.size());
        if (result != null) emitted.add(result);
        emitted.addAll(ctx.sent);
        String problem = check(frame, emitted, direction);
        if (problem != null) {
            LOG.log(Level.WARNING, endpoint.logPrefix + "frame interceptor result rejected for "
                    + describe(frame, direction) + ": " + problem + "; passing the frame on unchanged");
            return List.of(frame);
        }
        return withEndStream(frame, emitted);
    }

    private static String describe(Http2Frame frame, FrameDirection direction) {
        return frame.typeName() + " on stream " + frame.streamId() + " " + direction.name().toLowerCase(java.util.Locale.ROOT);
    }

    /** Whether the frame ends its stream. */
    private static boolean endsStream(Http2Frame frame) {
        return frame instanceof Http2Frame.Data d && d.endStream() || frame instanceof Http2Frame.Headers h && h.endStream();
    }

    private static boolean isMessage(Http2Frame frame) {
        return frame instanceof Http2Frame.Data || frame instanceof Http2Frame.Headers;
    }

    /** Why the interceptor's result for {@code original} cannot be used, or null if it can. */
    private String check(Http2Frame original, List<HttpFrame> emitted, FrameDirection direction) {
        List<Http2Frame> out = new ArrayList<>(emitted.size());
        for (HttpFrame f : emitted) {
            if (!(f instanceof Http2Frame h2)) return "not an HTTP/2 frame: " + f;
            out.add(h2);
        }
        boolean readOnly = original instanceof Http2Frame.Ping || original instanceof Http2Frame.WindowUpdate
                || original instanceof Http2Frame.Settings s && s.ack() || original instanceof Http2Frame.PushPromise;
        if (readOnly) {
            return out.size() == 1 && out.getFirst().equals(original) ? null
                    : original.typeName() + (original instanceof Http2Frame.Settings ? " ACK" : "") + " is read-only";
        }
        boolean droppable = original instanceof Http2Frame.Data || original instanceof Http2Frame.Priority
                || original instanceof Http2Frame.Unknown;
        if (!droppable) {
            if (out.isEmpty()) return original.typeName() + " cannot be dropped";
            if (out.getFirst().getClass() != original.getClass()) {
                return original.typeName() + " can only be replaced by " + original.typeName() + ", not " + out.getFirst().typeName();
            }
        }
        int stream = original.streamId();
        int lastMessage = -1;
        for (int i = 0; i < out.size(); i++) {
            Http2Frame f = out.get(i);
            if (f instanceof Http2Frame.Unknown u) {
                if (u.streamId() != 0 && u.streamId() != stream) return "an extension frame on another stream (" + u.streamId() + ")";
                if (u.payload().length > MAX_PAYLOAD) return "an extension frame of more than " + MAX_PAYLOAD + " bytes";
                continue;
            }
            if (f.streamId() != stream) return f.typeName() + " on stream " + f.streamId() + "; stream ids are read-only";
            String problem = switch (original) {
                case Http2Frame.Data d -> f instanceof Http2Frame.Data ? null
                        : f instanceof Http2Frame.Headers ? (d.endStream() ? null : "HEADERS after DATA that does not end the stream")
                        : f.typeName() + " in place of DATA";
                case Http2Frame.Headers h -> f instanceof Http2Frame.Headers ? null : f.typeName() + " in place of HEADERS";
                case Http2Frame.Priority p -> !(f instanceof Http2Frame.Priority q) ? f.typeName() + " in place of PRIORITY"
                        : q.streamDependency() == stream ? "a stream that depends on itself" : null;
                case Http2Frame.RstStream r -> i == 0 ? null : "a second " + f.typeName();
                case Http2Frame.GoAway g -> i > 0 ? "a second " + f.typeName()
                        : ((Http2Frame.GoAway) f).lastStreamId() != g.lastStreamId() ? "the last stream id is read-only"
                        : ((Http2Frame.GoAway) f).debugData().length > MAX_PAYLOAD ? "more than " + MAX_PAYLOAD + " bytes of debug data"
                        : null;
                case Http2Frame.Settings s -> i > 0 ? "a second " + f.typeName()
                        : settingsProblem(s, (Http2Frame.Settings) f, direction);
                default -> f.typeName() + " in place of " + original.typeName();
            };
            if (problem != null) return problem;
            if (f instanceof Http2Frame.Headers h) {
                if (lastMessage >= 0 && original instanceof Http2Frame.Data && out.get(lastMessage) instanceof Http2Frame.Headers) {
                    return "more than one HEADERS after DATA";
                }
                try {
                    Field.validate(h.fields());
                } catch (IllegalArgumentException e) {
                    return "invalid header block: " + e.getMessage();
                }
            } else if (f instanceof Http2Frame.Data && lastMessage >= 0 && out.get(lastMessage) instanceof Http2Frame.Headers
                    && original instanceof Http2Frame.Data) {
                return "DATA after the trailers";
            }
            if (isMessage(f)) lastMessage = i;
        }
        if (endsStream(original) && lastMessage >= 0) {
            for (int i = lastMessage + 1; i < out.size(); i++) {
                if (out.get(i).streamId() == stream) return "a frame on the stream after the one that ends it";
            }
        }
        return null;
    }

    /** Why an edited SETTINGS frame cannot be used, or null. */
    private String settingsProblem(Http2Frame.Settings original, Http2Frame.Settings edited, FrameDirection direction) {
        if (edited.ack()) return "SETTINGS cannot become an ACK";
        if (direction.inbound()) return endpoint.stricterSettings(original.values(), edited.values());
        for (int id : DEFINED_SETTINGS) {
            if (!Objects.equals(original.values().get(id), edited.values().get(id))) {
                return "the proxy's own " + Http2Frame.settingName(id) + " is read-only";
            }
        }
        return null;
    }

    /**
     * The checked result with END_STREAM where it belongs: on the last DATA or HEADERS frame if the
     * original ended its stream (an empty DATA frame added if there is none), nowhere else.
     */
    private static List<Http2Frame> withEndStream(Http2Frame original, List<HttpFrame> emitted) {
        boolean ends = endsStream(original);
        int last = -1;
        for (int i = 0; i < emitted.size(); i++) {
            if (isMessage((Http2Frame) emitted.get(i))) last = i;
        }
        List<Http2Frame> out = new ArrayList<>(emitted.size() + 1);
        for (int i = 0; i < emitted.size(); i++) {
            Http2Frame f = (Http2Frame) emitted.get(i);
            boolean end = ends && i == last;
            if (f instanceof Http2Frame.Data d && d.endStream() != end) f = d.withEndStream(end);
            if (f instanceof Http2Frame.Headers h && h.endStream() != end) f = h.withEndStream(end);
            out.add(f);
        }
        if (ends && last < 0) out.add(new Http2Frame.Data(original.streamId(), Http2Endpoint.EMPTY, true));
        return out;
    }

    /** One interceptor call's {@link FrameContext}. */
    private final class Context implements FrameContext {
        private final int streamId;
        private final FlowContext flow;
        /** Frames added with {@link #send}, in order. */
        final List<HttpFrame> sent = new ArrayList<>(0);
        volatile boolean done;

        Context(int streamId, FlowContext flow) {
            this.streamId = streamId;
            this.flow = flow;
        }

        @Override
        public FrameProtocol protocol() {
            return FrameProtocol.HTTP_2;
        }

        @Override
        public long connectionId() {
            return flow != null ? flow.getConnectionId() : endpoint.frameConnectionId();
        }

        @Override
        public InetSocketAddress clientAddress() {
            return flow != null ? flow.getClientAddress() : endpoint.frameClientAddress();
        }

        @Override
        public String server() {
            return endpoint.frameServer();
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
            return "FrameContext[h2, connection " + connectionId() + ", stream " + streamId + "]";
        }
    }
}
