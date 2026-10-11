package io.github.mahmoudimus.http3;

import java.util.Locale;

/**
 * Checks which frames the peer may send on one stream, and in what order (RFC 9114 §4.1, §6.2.1,
 * §7.2). Feed it every frame read from the stream, then the end of the stream. One validator per
 * stream; not thread-safe.
 *
 * <ul>
 *   <li><b>Control stream</b> ({@link #forControlStream}): SETTINGS first (else
 *       H3_MISSING_SETTINGS) and only once; no DATA, HEADERS or PUSH_PROMISE; MAX_PUSH_ID only from
 *       a client, never decreasing; GOAWAY never increasing, and from a server naming a
 *       client-initiated bidirectional stream; CANCEL_PUSH to a server within the MAX_PUSH_ID it
 *       received. Its end is a connection error H3_CLOSED_CRITICAL_STREAM.
 *   <li><b>Request stream</b> ({@link #forRequestStream}): HEADERS, then any number of DATA, then
 *       optionally trailing HEADERS, and nothing after that; a response may be preceded by interim
 *       (1xx) HEADERS, which the caller reports with {@link #interimResponse()}. PUSH_PROMISE only
 *       from a server, anywhere. No SETTINGS, GOAWAY, MAX_PUSH_ID or CANCEL_PUSH. A request
 *       stream that ends before its HEADERS is a stream error H3_REQUEST_INCOMPLETE.
 *   <li><b>Push stream</b> ({@link #forPushStream}): as a response on a request stream, without
 *       PUSH_PROMISE.
 * </ul>
 *
 * <p>Frames of unknown and reserved types are allowed anywhere except before SETTINGS on the
 * control stream. Wrong frames are connection errors H3_FRAME_UNEXPECTED.
 */
public final class Http3StreamValidator {

    /** Which end of the connection this endpoint is. */
    public enum Role {
        /** The client, which opens request streams. */
        CLIENT,
        /** The server, which answers them. */
        SERVER
    }

    /** The kind of stream a validator checks. */
    public enum Kind {
        /** A control stream. */
        CONTROL,
        /** A request stream: a request, or the response to it. */
        REQUEST,
        /** A push stream. */
        PUSH
    }

    private enum State {
        /** Expecting the (next) HEADERS of a message. */
        HEADERS,
        /** After the header section: DATA or trailers. */
        BODY,
        /** After the trailers. */
        DONE
    }

    private final Kind kind;
    private final Role local;
    private final long streamId;

    private boolean settingsReceived;
    private long maxPushId = -1;
    private long goAwayId = -1;

    private State state = State.HEADERS;
    private boolean dataReceived;

    private Http3StreamValidator(Kind kind, Role local, long streamId) {
        this.kind = kind;
        this.local = local;
        this.streamId = streamId;
    }

    /**
     * A validator for the peer's control stream.
     *
     * @param local which end this endpoint is
     * @return the validator
     */
    public static Http3StreamValidator forControlStream(Role local) {
        return new Http3StreamValidator(Kind.CONTROL, local, -1);
    }

    /**
     * A validator for the frames received on a request stream: a request when {@code local} is
     * the server, a response when it is the client.
     *
     * @param streamId the stream
     * @param local which end this endpoint is
     * @return the validator
     */
    public static Http3StreamValidator forRequestStream(long streamId, Role local) {
        checkStreamId(streamId);
        return new Http3StreamValidator(Kind.REQUEST, local, streamId);
    }

    /**
     * A validator for a push stream, after its push ID; only clients receive these.
     *
     * @param streamId the stream
     * @param local which end this endpoint is; only {@link Role#CLIENT}
     * @return the validator
     */
    public static Http3StreamValidator forPushStream(long streamId, Role local) {
        checkStreamId(streamId);
        if (local != Role.CLIENT) throw new IllegalArgumentException("only clients receive push streams");
        return new Http3StreamValidator(Kind.PUSH, local, streamId);
    }

    /**
     * The kind of stream this validator checks.
     *
     * @return the kind
     */
    public Kind kind() {
        return kind;
    }

    /**
     * Whether the control stream's SETTINGS frame has arrived.
     *
     * @return whether SETTINGS arrived
     */
    public boolean settingsReceived() {
        return settingsReceived;
    }

    /**
     * Whether a complete header section has been received on a request or push stream.
     *
     * @return whether a header section arrived
     */
    public boolean headersReceived() {
        return state != State.HEADERS;
    }

    /**
     * Whether trailers have been received on a request or push stream.
     *
     * @return whether trailers arrived
     */
    public boolean trailersReceived() {
        return state == State.DONE;
    }

    /**
     * Checks the next frame, including the identifiers in GOAWAY, MAX_PUSH_ID and CANCEL_PUSH.
     *
     * @param frame the frame
     * @throws Http3Exception a connection error if the frame is not allowed here
     */
    public void onFrame(Http3Frame frame) throws Http3Exception {
        onFrame(frame.type());
        if (kind != Kind.CONTROL) return;
        switch (frame) {
            case Http3Frame.MaxPushId m -> {
                if (m.pushId() < maxPushId) {
                    throw idError("MAX_PUSH_ID went down from " + maxPushId + " to " + m.pushId());
                }
                maxPushId = m.pushId();
            }
            case Http3Frame.GoAway g -> {
                if (local == Role.CLIENT && g.id() % 4 != 0) {
                    throw idError("GOAWAY from a server names stream " + g.id() + ", not a client-initiated bidirectional stream");
                }
                if (goAwayId >= 0 && g.id() > goAwayId) {
                    throw idError("GOAWAY identifier went up from " + goAwayId + " to " + g.id());
                }
                goAwayId = g.id();
            }
            case Http3Frame.CancelPush c -> {
                if (local == Role.SERVER && c.pushId() > maxPushId) {
                    throw idError("CANCEL_PUSH for push " + c.pushId() + " beyond MAX_PUSH_ID "
                            + (maxPushId < 0 ? "(none sent)" : maxPushId));
                }
            }
            default -> {}
        }
    }

    /**
     * Checks the next frame by type alone.
     *
     * @param type the frame type
     * @throws Http3Exception a connection error if the frame is not allowed here
     */
    public void onFrame(long type) throws Http3Exception {
        if (kind == Kind.CONTROL) {
            onControlFrame(type);
        } else {
            onMessageFrame(type);
        }
    }

    private void onControlFrame(long type) throws Http3Exception {
        if (!settingsReceived) {
            if (type != Http3FrameType.SETTINGS) {
                throw Http3Exception.connectionError(Http3ErrorCode.H3_MISSING_SETTINGS,
                        "first frame on the control stream is " + Http3FrameType.name(type) + ", not SETTINGS");
            }
            settingsReceived = true;
            return;
        }
        if (type == Http3FrameType.SETTINGS) throw unexpected("a second SETTINGS frame on the control stream");
        if (type == Http3FrameType.DATA || type == Http3FrameType.HEADERS || type == Http3FrameType.PUSH_PROMISE) {
            throw unexpected(Http3FrameType.name(type) + " frame on the control stream");
        }
        if (type == Http3FrameType.MAX_PUSH_ID && local == Role.CLIENT) throw unexpected("MAX_PUSH_ID frame from a server");
    }

    private void onMessageFrame(long type) throws Http3Exception {
        if (type == Http3FrameType.DATA) {
            if (state != State.BODY) {
                throw unexpected("DATA frame " + (state == State.HEADERS ? "before HEADERS" : "after trailers") + " on stream " + streamId);
            }
            dataReceived = true;
        } else if (type == Http3FrameType.HEADERS) {
            switch (state) {
                case HEADERS -> state = State.BODY;
                case BODY -> state = State.DONE;
                case DONE -> throw unexpected("HEADERS frame after trailers on stream " + streamId);
            }
        } else if (type == Http3FrameType.PUSH_PROMISE) {
            if (kind == Kind.PUSH) throw unexpected("PUSH_PROMISE frame on push stream " + streamId);
            if (local == Role.SERVER) throw unexpected("PUSH_PROMISE frame from a client on stream " + streamId);
        } else if (type == Http3FrameType.SETTINGS || type == Http3FrameType.GOAWAY
                || type == Http3FrameType.MAX_PUSH_ID || type == Http3FrameType.CANCEL_PUSH) {
            throw unexpected(Http3FrameType.name(type) + " frame on " + kind.name().toLowerCase(Locale.ROOT)
                    + " stream " + streamId);
        }
    }

    /**
     * Reports that the HEADERS just received held an interim (1xx) response, so another header
     * section must follow (RFC 9114 §4.1). Only valid on a response, directly after its HEADERS.
     *
     * @throws IllegalStateException otherwise
     */
    public void interimResponse() {
        if (kind == Kind.CONTROL || local != Role.CLIENT || state != State.BODY || dataReceived) {
            throw new IllegalStateException("no interim response header section to report");
        }
        state = State.HEADERS;
    }

    /**
     * Reports the clean end of the stream.
     *
     * @throws Http3Exception a connection error H3_CLOSED_CRITICAL_STREAM for the control stream; a
     *     stream error H3_REQUEST_INCOMPLETE for a request that ended before its header section,
     *     or H3_MESSAGE_ERROR for a response that did
     */
    public void onEndOfStream() throws Http3Exception {
        if (kind == Kind.CONTROL) {
            throw Http3Exception.connectionError(Http3ErrorCode.H3_CLOSED_CRITICAL_STREAM, "the control stream was closed");
        }
        if (state == State.HEADERS) {
            if (local == Role.SERVER) {
                throw Http3Exception.streamError(streamId, Http3ErrorCode.H3_REQUEST_INCOMPLETE,
                        "request stream ended before a complete header section");
            }
            throw Http3Exception.streamError(streamId, Http3ErrorCode.H3_MESSAGE_ERROR,
                    "stream ended before a final response header section");
        }
    }

    private static Http3Exception unexpected(String message) {
        return Http3Exception.connectionError(Http3ErrorCode.H3_FRAME_UNEXPECTED, message);
    }

    private static Http3Exception idError(String message) {
        return Http3Exception.connectionError(Http3ErrorCode.H3_ID_ERROR, message);
    }

    private static void checkStreamId(long streamId) {
        if (streamId < 0 || streamId > QuicVarInt.MAX_VALUE) throw new IllegalArgumentException("bad stream ID " + streamId);
    }

    /**
     * The peer's unidirectional streams (RFC 9114 §6.2, RFC 9204 §4.2): at most one control
     * stream, one QPACK encoder stream and one QPACK decoder stream, and push streams only from a
     * server. Not thread-safe.
     */
    public static final class UnidirectionalStreams {

        private final Role local;
        private boolean control;
        private boolean encoder;
        private boolean decoder;

        /**
         * Tracks the peer's unidirectional streams.
         *
         * @param local which end this endpoint is
         */
        public UnidirectionalStreams(Role local) {
            this.local = local;
        }

        /**
         * Checks a new stream of the given type.
         *
         * @param type the stream type
         * @return true if the stream is to be read; false for an unknown or reserved type, whose
         *     stream the caller abandons (reading stopped with H3_STREAM_CREATION_ERROR) or discards
         * @throws Http3Exception a connection error H3_STREAM_CREATION_ERROR for a second control,
         *     encoder or decoder stream, or a push stream opened by a client
         */
        public boolean onStream(long type) throws Http3Exception {
            if (type == Http3StreamType.CONTROL) {
                control = once(control, type);
            } else if (type == Http3StreamType.QPACK_ENCODER) {
                encoder = once(encoder, type);
            } else if (type == Http3StreamType.QPACK_DECODER) {
                decoder = once(decoder, type);
            } else if (type == Http3StreamType.PUSH) {
                if (local == Role.SERVER) {
                    throw Http3Exception.connectionError(Http3ErrorCode.H3_STREAM_CREATION_ERROR, "a client opened a push stream");
                }
            } else {
                return false;
            }
            return true;
        }

        /**
         * Reports that a stream of this type ended or was reset.
         *
         * @param type the stream type
         * @throws Http3Exception a connection error H3_CLOSED_CRITICAL_STREAM for a control, encoder
         *     or decoder stream
         */
        public void onStreamClosed(long type) throws Http3Exception {
            if (Http3StreamType.isCritical(type)) {
                throw Http3Exception.connectionError(Http3ErrorCode.H3_CLOSED_CRITICAL_STREAM,
                        "the " + Http3StreamType.name(type) + " stream was closed");
            }
        }

        private static boolean once(boolean seen, long type) throws Http3Exception {
            if (seen) {
                throw Http3Exception.connectionError(Http3ErrorCode.H3_STREAM_CREATION_ERROR,
                        "a second " + Http3StreamType.name(type) + " stream");
            }
            return true;
        }
    }
}
