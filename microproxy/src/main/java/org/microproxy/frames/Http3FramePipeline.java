package org.microproxy.frames;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.Objects;

/**
 * Runs a {@link FrameInterceptor} over HTTP/3 traffic given as the bytes of its streams: it reads
 * frames from a request stream or a control stream, shows each to the interceptor as an {@link
 * Http3Frame} (HEADERS decoded through QPACK), and writes what comes back to an output stream.
 *
 * <p>The proxy does not terminate QUIC, so it never sees live HTTP/3: it steers HTTP/3 clients to
 * HTTP/2 by removing {@code h3} from {@code Alt-Svc} instead. This pipeline is where a QUIC layer
 * will plug in, and today it processes HTTP/3 streams captured or relayed by other means. It needs
 * the optional {@code http3-codec} module on the class path ({@link #available()}).
 *
 * <pre>{@code
 * Http3FramePipeline pipeline = Http3FramePipeline.builder(interceptor)
 *         .direction(FrameDirection.FROM_CLIENT)   // whose frames these are
 *         .build();
 * pipeline.controlStream(2, clientControlIn, controlOut);    // stream type, SETTINGS, ...
 * pipeline.encoderStream(clientQpackEncoderIn);              // only if the client's QPACK uses a dynamic table
 * pipeline.requestStream(0, requestStreamIn, requestOut);    // HEADERS, DATA, trailers
 * }</pre>
 *
 * <p>A pipeline stands for one sender's streams on one connection: it keeps that sender's QPACK
 * decoder, so feed it the sender's QPACK encoder stream ({@link #encoderStream}) when its field
 * sections use the dynamic table, before the request streams that need it. Field sections are
 * written back with static-only QPACK, which never needs an encoder stream. Its methods may run on
 * several threads at once, one stream each.
 *
 * <p>The rules are {@link FrameInterceptor}'s, adapted to HTTP/3, whose frames carry no stream id
 * and no END_STREAM (a message ends with its stream):
 *
 * <table>
 *   <caption>Allowed results per HTTP/3 frame type</caption>
 *   <tr><th>Frame</th><th>May be edited</th><th>May be dropped</th><th>May be followed by</th></tr>
 *   <tr><td>DATA</td><td>the payload</td><td>yes</td><td>DATA; HEADERS (trailers); extension frames</td></tr>
 *   <tr><td>HEADERS</td><td>the fields</td><td>no</td><td>HEADERS; extension frames</td></tr>
 *   <tr><td>SETTINGS</td><td>the values (valid HTTP/3 settings)</td><td>no</td><td>extension frames</td></tr>
 *   <tr><td>extension and reserved (grease) frames</td><td>everything</td><td>yes</td><td>extension frames</td></tr>
 *   <tr><td>GOAWAY, MAX_PUSH_ID, CANCEL_PUSH, PUSH_PROMISE</td><td>nothing</td><td>no</td><td>nothing</td></tr>
 * </table>
 *
 * <p>Header fields must pass {@link Field#validate}, and frames must keep the stream's order: a
 * request or response is HEADERS (after interim 1xx HEADERS, for a response), DATA, then optional
 * trailing HEADERS. A result that breaks a rule is logged and the original frame written instead;
 * so is a frame whose interceptor throws. If an earlier result ended the message (by adding
 * trailers) and the input goes on with DATA, the stream fails with H3_FRAME_UNEXPECTED. Input that
 * breaks HTTP/3 fails with an {@code IOException} (the codec's {@code Http3Exception}), after the
 * frames before it were written.
 */
public final class Http3FramePipeline {

    private static final String CODEC_CLASS = "io.github.mahmoudimus.http3.Http3FrameReader";

    /** What building a pipeline without the codec fails with. */
    static final String MISSING = "Http3FramePipeline needs the http3-codec module (io.github.mahmoudimus:http3-codec)"
            + " on the class path; add its jar or use the microproxy-starlark -all jar, which bundles it";

    private static final boolean PRESENT = present();

    private final Http3Streams streams;

    private Http3FramePipeline(Builder b) {
        this.streams = new Http3Streams(b.interceptor, b.direction, b.connectionId, b.clientAddress, b.server,
                b.qpackMaxTableCapacity, b.qpackBlockedStreams, b.maxFramePayloadSize, b.maxFieldSectionSize);
    }

    /**
     * Whether the optional {@code http3-codec} module is on the class path, so that a pipeline can
     * be built.
     *
     * @return whether the codec is present
     */
    public static boolean available() {
        return PRESENT;
    }

    private static boolean present() {
        try {
            Class.forName(CODEC_CLASS, false, Http3FramePipeline.class.getClassLoader());
            return true;
        } catch (ClassNotFoundException | LinkageError e) {
            return false;
        }
    }

    /**
     * Starts a pipeline that shows frames to {@code interceptor}.
     *
     * @param interceptor the interceptor
     * @return a builder
     */
    public static Builder builder(FrameInterceptor interceptor) {
        return new Builder(Objects.requireNonNull(interceptor, "interceptor"));
    }

    /** Options for {@link Http3FramePipeline}. */
    public static final class Builder {
        private final FrameInterceptor interceptor;
        private FrameDirection direction = FrameDirection.FROM_CLIENT;
        private long connectionId = -1;
        private InetSocketAddress clientAddress;
        private String server;
        private long qpackMaxTableCapacity;
        private int qpackBlockedStreams;
        private int maxFramePayloadSize = 64 * 1024;
        private long maxFieldSectionSize = 64 * 1024;

        private Builder(FrameInterceptor interceptor) {
            this.interceptor = interceptor;
        }

        /**
         * Whose frames these are, as the interceptor is told: {@link FrameDirection#FROM_CLIENT} or
         * {@link FrameDirection#TO_SERVER} for a client's (requests), {@link FrameDirection#FROM_SERVER}
         * or {@link FrameDirection#TO_CLIENT} for a server's (responses). Default {@code FROM_CLIENT}.
         *
         * @param direction the direction
         * @return this builder
         */
        public Builder direction(FrameDirection direction) {
            this.direction = Objects.requireNonNull(direction, "direction");
            return this;
        }

        /**
         * The connection id the interceptor is told ({@link FrameContext#connectionId()}); default -1.
         *
         * @param connectionId the id
         * @return this builder
         */
        public Builder connectionId(long connectionId) {
            this.connectionId = connectionId;
            return this;
        }

        /**
         * The client address the interceptor is told; default none.
         *
         * @param clientAddress the address, or null
         * @return this builder
         */
        public Builder clientAddress(InetSocketAddress clientAddress) {
            this.clientAddress = clientAddress;
            return this;
        }

        /**
         * The server ({@code host:port}) the interceptor is told; default none.
         *
         * @param server the server, or null
         * @return this builder
         */
        public Builder server(String server) {
            this.server = server;
            return this;
        }

        /**
         * The QPACK dynamic table the sender may use: the SETTINGS_QPACK_MAX_TABLE_CAPACITY and
         * SETTINGS_QPACK_BLOCKED_STREAMS its peer advertised. Default 0 and 0: static-only.
         *
         * @param maxTableCapacity the table capacity, 0 or more
         * @param blockedStreams the most streams that may wait for the encoder stream, 0 or more
         * @return this builder
         */
        public Builder qpack(long maxTableCapacity, int blockedStreams) {
            if (maxTableCapacity < 0 || blockedStreams < 0) throw new IllegalArgumentException("negative QPACK limit");
            this.qpackMaxTableCapacity = maxTableCapacity;
            this.qpackBlockedStreams = blockedStreams;
            return this;
        }

        /**
         * The largest frame payload read (default 64 KiB); a longer DATA frame is shown in pieces
         * of this size, any other longer frame fails the stream.
         *
         * @param maxFramePayloadSize the limit in bytes, 1 or more
         * @return this builder
         */
        public Builder maxFramePayloadSize(int maxFramePayloadSize) {
            if (maxFramePayloadSize < 1) throw new IllegalArgumentException("maxFramePayloadSize must be positive");
            this.maxFramePayloadSize = maxFramePayloadSize;
            return this;
        }

        /**
         * The largest decoded field section accepted (default 64 KiB).
         *
         * @param maxFieldSectionSize the limit in bytes, 1 or more
         * @return this builder
         */
        public Builder maxFieldSectionSize(long maxFieldSectionSize) {
            if (maxFieldSectionSize < 1) throw new IllegalArgumentException("maxFieldSectionSize must be positive");
            this.maxFieldSectionSize = maxFieldSectionSize;
            return this;
        }

        /**
         * Builds the pipeline.
         *
         * @return the pipeline
         * @throws IllegalStateException if the {@code http3-codec} module is not on the class path
         */
        public Http3FramePipeline build() {
            if (!available()) throw new IllegalStateException(MISSING);
            return new Http3FramePipeline(this);
        }
    }

    /**
     * Processes a request stream (a bidirectional stream: a request from a client, or the
     * response to it from a server) until its end, writing the result to {@code out}, which is
     * flushed after each frame and not closed.
     *
     * @param streamId the QUIC stream id, 0 or more ({@link FrameContext#streamId()})
     * @param in the stream's bytes
     * @param out where the stream's new bytes go
     * @throws IOException if reading or writing fails, or the input breaks HTTP/3
     */
    public void requestStream(long streamId, InputStream in, OutputStream out) throws IOException {
        if (streamId < 0) throw new IllegalArgumentException("bad stream id " + streamId);
        streams.requestStream(streamId, Objects.requireNonNull(in, "in"), Objects.requireNonNull(out, "out"));
    }

    /**
     * Processes a control stream, from its stream type (which must be 0x00, the control stream's)
     * until its end, writing the result, stream type first, to {@code out}, which is flushed after
     * each frame and not closed.
     *
     * @param streamId the QUIC stream id ({@link FrameContext#streamId()}), or -1 if unknown
     * @param in the stream's bytes
     * @param out where the stream's new bytes go
     * @throws IOException if reading or writing fails, or the input breaks HTTP/3
     */
    public void controlStream(long streamId, InputStream in, OutputStream out) throws IOException {
        streams.controlStream(streamId, Objects.requireNonNull(in, "in"), Objects.requireNonNull(out, "out"));
    }

    /**
     * Reads the sender's QPACK encoder stream, from its stream type (0x02) until its end, so that
     * field sections that use the dynamic table can be decoded. Feed it before the request streams
     * whose sections need its instructions; a section that needs instructions not given yet fails
     * its stream.
     *
     * @param in the encoder stream's bytes
     * @throws IOException if reading fails, or the stream is not a valid QPACK encoder stream
     */
    public void encoderStream(InputStream in) throws IOException {
        streams.encoderStream(Objects.requireNonNull(in, "in"));
    }
}
